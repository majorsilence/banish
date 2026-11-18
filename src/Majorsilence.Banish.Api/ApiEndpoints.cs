using System.Security.Claims;
using System.Text;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Store.Api;

namespace Majorsilence.Banish.Api;

public sealed record FailureReport(string Address, string Rule);

public static class ApiEndpoints
{
    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api/v1");

        api.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

        // ---- agents -----------------------------------------------------------------------
        var agent = api.MapGroup("").RequireAuthorization(Policies.Agent);

        agent.MapGet("/bans/active", async (IBanStore store, CancellationToken ct) =>
            Results.Ok(await store.GetActiveAsync(ct)));

        agent.MapGet("/bans/active/by-address", async (string address, IBanStore store, CancellationToken ct) =>
            await store.GetActiveByAddressAsync(Normalize(address), ct) is { } ban ? Results.Ok(ban) : Results.NotFound());

        agent.MapGet("/bans/prior-count", async (string address, IBanStore store, CancellationToken ct) =>
            Results.Ok(new CountResponse(await store.CountPriorAsync(Normalize(address), ct))));

        agent.MapPost("/bans", async (Ban ban, ClaimsPrincipal user, IBanStore store, AllowlistProvider allow, TimeProvider time, CancellationToken ct) =>
        {
            if (!IpAddressUtil.TryParseNetwork(ban.Address, out var network) || !IpAddressUtil.IsBannable(network))
            {
                return Results.BadRequest(new { error = "Address is not a bannable IP address or CIDR range." });
            }

            ban.Address = IpAddressUtil.Format(network);
            var now = time.GetUtcNow().UtcDateTime;
            ban.Id = Guid.NewGuid();
            ban.CreatedUtc = now;
            ban.UpdatedUtc = now;
            ban.RemovedUtc = null;
            ban.RemovedBy = null;
            if (ban.Reason.Length > 512)
            {
                ban.Reason = ban.Reason[..512];
            }

            if (!user.IsInRole(ApiRoles.Admin))
            {
                // An agent may only report local bans, as itself, and never against an allow-listed address.
                await allow.RefreshAsync(store, ct);
                if (allow.Current.Overlaps(network))
                {
                    return Results.Conflict(new { error = "Address is allow-listed." });
                }

                ban.Source = BanSources.Local;
                ban.MachineName = user.Identity!.Name!;
                ban.CreatedBy = user.Identity.Name;
            }
            else
            {
                ban.CreatedBy ??= user.Identity!.Name;
                ban.Source = string.IsNullOrWhiteSpace(ban.Source) ? BanSources.Manual : ban.Source;
            }

            return Results.Ok(await store.AddAsync(ban, ct));
        });

        agent.MapGet("/allowlist", async (IBanStore store, CancellationToken ct) =>
            Results.Ok(await store.GetAllowlistAsync(ct)));

        agent.MapPost("/agents/heartbeat", async (AgentInfo info, ClaimsPrincipal user, IBanStore store, CancellationToken ct) =>
        {
            if (!user.IsInRole(ApiRoles.Admin))
            {
                info.MachineName = user.Identity!.Name!;
            }

            if (string.IsNullOrWhiteSpace(info.MachineName))
            {
                return Results.BadRequest(new { error = "MachineName is required." });
            }

            await store.HeartbeatAsync(info, ct);
            return Results.NoContent();
        });

        agent.MapPost("/failures", async (FailureReport report, BanEngine engine, TimeProvider time, CancellationToken ct) =>
        {
            if (!IpAddressUtil.TryParseAddress(report.Address, out var address) || string.IsNullOrWhiteSpace(report.Rule))
            {
                return Results.BadRequest(new { error = "An IP address and a rule name are required." });
            }

            var ban = await engine.ReportFailureAsync(new FailureEvent(address, report.Rule, time.GetUtcNow().UtcDateTime), ct);
            return Results.Ok(new { banned = ban is not null, ban });
        });

        agent.MapGet("/blocklist.txt", async (IBanStore store, CancellationToken ct) =>
        {
            var active = await store.GetActiveAsync(ct);
            var sb = new StringBuilder();
            foreach (string address in active.Select(b => b.Address).Distinct().Order(StringComparer.Ordinal))
            {
                sb.Append(address).Append('\n');
            }

            return Results.Text(sb.ToString(), "text/plain");
        });

        // ---- viewers ----------------------------------------------------------------------
        var viewer = api.MapGroup("").RequireAuthorization(Policies.Viewer);

        viewer.MapGet("/bans", async (
            string? state, string? search, string? source, string? rule, string? machine, int? skip, int? take,
            IBanStore store, ClaimsPrincipal user, BanishOptions options, CancellationToken ct) =>
        {
            var page = await store.QueryAsync(new BanQuery
            {
                State = state ?? "active",
                Search = search,
                Source = source,
                RuleId = rule,
                MachineName = machine,
                Skip = skip ?? 0,
                Take = take ?? 50,
            }, ct);
            return Results.Ok(ShouldMask(user, options) ? page with { Items = page.Items.Select(IpMasker.Mask).ToList() } : page);
        });

        viewer.MapGet("/stats", async (IBanStore store, ClaimsPrincipal user, BanishOptions options, CancellationToken ct) =>
        {
            var stats = await store.GetStatsAsync(ct);
            return Results.Ok(ShouldMask(user, options) ? IpMasker.Mask(stats) : stats);
        });

        viewer.MapGet("/events", async (int? take, IBanStore store, ClaimsPrincipal user, BanishOptions options, CancellationToken ct) =>
        {
            var events = await store.GetEventsAsync(take ?? 100, ct);
            return Results.Ok(ShouldMask(user, options) ? events.Select(IpMasker.Mask).ToList() : events.ToList());
        });

        // ---- admins -----------------------------------------------------------------------
        var admin = api.MapGroup("").RequireAuthorization(Policies.Admin);

        admin.MapDelete("/bans", async (string address, string? actor, ClaimsPrincipal user, IBanStore store, CancellationToken ct) =>
        {
            if (!IpAddressUtil.TryNormalize(address, out string normalized))
            {
                return Results.BadRequest(new { error = "Not an IP address or CIDR range." });
            }

            string by = actor is { Length: > 0 } ? $"{user.Identity!.Name}/{actor}" : user.Identity!.Name!;
            return Results.Ok(new CountResponse(await store.RemoveAsync(normalized, by, ct)));
        });

        admin.MapGet("/sync", (IBlocklistSync sync) =>
            Results.Ok(new
            {
                sources = sync.Sources.Select(s => new { s.Name, s.Url, s.Enabled, s.Format, s.IntervalMinutes }),
                results = sync.LastResults,
            }));

        admin.MapPost("/sync/run", async (bool? dryRun, IBlocklistSync sync, CancellationToken ct) =>
            Results.Ok(await sync.RunAllAsync(dryRun ?? false, ct)));

        admin.MapPost("/bans/bulk", async (List<Ban> bans, ClaimsPrincipal user, IBanStore store, TimeProvider time, CancellationToken ct) =>
        {
            if (bans.Count > 5000)
            {
                return Results.BadRequest(new { error = "At most 5000 bans per request." });
            }

            var now = time.GetUtcNow().UtcDateTime;
            var valid = new List<Ban>(bans.Count);
            foreach (var ban in bans)
            {
                if (IpAddressUtil.TryParseNetwork(ban.Address, out var network) && IpAddressUtil.IsBannable(network))
                {
                    ban.Address = IpAddressUtil.Format(network);
                    ban.CreatedUtc = now;
                    ban.RemovedUtc = null;
                    ban.CreatedBy ??= user.Identity!.Name;
                    ban.Source = string.IsNullOrWhiteSpace(ban.Source) ? BanSources.Manual : ban.Source;
                    valid.Add(ban);
                }
            }

            return Results.Ok(new CountResponse(await store.AddRangeAsync(valid, ct)));
        });

        admin.MapPost("/bans/remove-by-source", async (RemoveBySourceRequest request, ClaimsPrincipal user, IBanStore store, CancellationToken ct) =>
            Results.Ok(new CountResponse(await store.RemoveBySourceAsync(request.Source, request.Except, request.Actor ?? user.Identity!.Name!, ct))));

        admin.MapPost("/allowlist", async (AllowEntry entry, ClaimsPrincipal user, IBanStore store, CancellationToken ct) =>
        {
            if (!IpAddressUtil.TryNormalize(entry.Address, out string normalized))
            {
                return Results.BadRequest(new { error = "Not an IP address or CIDR range." });
            }

            entry.Address = normalized;
            entry.Id = Guid.NewGuid();
            entry.CreatedBy ??= user.Identity!.Name;
            return Results.Ok(await store.AddAllowAsync(entry, ct));
        });

        admin.MapDelete("/allowlist", async (string address, IBanStore store, CancellationToken ct) =>
        {
            if (!IpAddressUtil.TryNormalize(address, out string normalized))
            {
                return Results.BadRequest(new { error = "Not an IP address or CIDR range." });
            }

            return Results.Ok(new CountResponse(await store.RemoveAllowAsync(normalized, ct) ? 1 : 0));
        });
    }

    /// <summary>Viewers (and anonymous readers) see partly hidden addresses; agents and admins see everything.</summary>
    internal static bool ShouldMask(ClaimsPrincipal user, BanishOptions options) =>
        options.Dashboard.MaskIps && !user.IsInRole(ApiRoles.Admin) && !user.IsInRole(ApiRoles.Agent);

    private static string Normalize(string address) =>
        IpAddressUtil.TryNormalize(address, out string normalized) ? normalized : address;
}
