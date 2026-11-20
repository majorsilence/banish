using Majorsilence.Banish.Core;
using Microsoft.EntityFrameworkCore;

namespace Majorsilence.Banish.Store.Ef;

/// <summary>IBanStore over EF Core: SQLite, PostgreSQL, SQL Server or MySQL.</summary>
public sealed class EfBanStore : IBanStore
{
    private readonly IDbContextFactory<BanishDbContext> _factory;
    private readonly TimeProvider _time;
    private readonly string _machineName;

    public EfBanStore(IDbContextFactory<BanishDbContext> factory, string machineName, TimeProvider? time = null)
    {
        _factory = factory;
        _machineName = machineName;
        _time = time ?? TimeProvider.System;
    }

    private DateTime Now => _time.GetUtcNow().UtcDateTime;

    /// <summary>Creates the schema, or upgrades an existing one, with the provider's migrations.</summary>
    public async Task MigrateAsync(CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        await SchemaMigrator.MigrateAsync(db, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Ban> AddAsync(Ban ban, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = Now;
        var existing = await db.Bans
            .Where(b => b.Address == ban.Address && b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now))
            .OrderBy(b => b.CreatedUtc)
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);

        if (existing is not null)
        {
            // Extend rather than duplicate: keep the later expiry (permanent wins).
            existing.ExpiresUtc = existing.ExpiresUtc is null || ban.ExpiresUtc is null
                ? null
                : (existing.ExpiresUtc > ban.ExpiresUtc ? existing.ExpiresUtc : ban.ExpiresUtc);
            existing.Hits += ban.Hits;
            existing.UpdatedUtc = now;
            db.BanEvents.Add(NewEvent(existing, BanEventKinds.Extended, ban.CreatedBy, ban.Reason));
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return existing;
        }

        if (ban.CreatedUtc == default)
        {
            ban.CreatedUtc = now;
        }

        ban.UpdatedUtc = now;
        if (string.IsNullOrEmpty(ban.MachineName))
        {
            ban.MachineName = _machineName;
        }

        db.Bans.Add(ban);
        db.BanEvents.Add(NewEvent(ban, BanEventKinds.Banned, ban.CreatedBy, ban.Reason));
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return ban;
    }

    public async Task<int> AddRangeAsync(IReadOnlyCollection<Ban> bans, CancellationToken cancellationToken)
    {
        int added = 0;
        var now = Now;
        foreach (var batch in bans.Chunk(1000))
        {
            await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            var existing = new HashSet<string>(StringComparer.Ordinal);
            foreach (var chunk in batch.Select(b => b.Address).Chunk(500))
            {
                var found = await db.Bans.AsNoTracking()
                    .Where(b => chunk.Contains(b.Address) && b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now))
                    .Select(b => b.Address)
                    .ToListAsync(cancellationToken).ConfigureAwait(false);
                existing.UnionWith(found);
            }

            foreach (var ban in batch.Where(b => !existing.Contains(b.Address)).DistinctBy(b => b.Address))
            {
                ban.Id = Guid.NewGuid();
                ban.CreatedUtc = ban.CreatedUtc == default ? now : ban.CreatedUtc;
                ban.UpdatedUtc = now;
                if (string.IsNullOrEmpty(ban.MachineName))
                {
                    ban.MachineName = _machineName;
                }

                db.Bans.Add(ban);
                added++;
            }

            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return added;
    }

    public async Task<int> RemoveAsync(string address, string removedBy, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = Now;
        var bans = await db.Bans
            .Where(b => b.Address == address && b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var ban in bans)
        {
            ban.RemovedUtc = now;
            ban.RemovedBy = removedBy;
            ban.UpdatedUtc = now;
            db.BanEvents.Add(NewEvent(ban, BanEventKinds.Unbanned, removedBy, null));
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return bans.Count;
    }

    public async Task<int> RemoveBySourceAsync(string source, IReadOnlyCollection<string> except, string removedBy, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = Now;
        var keep = except.ToHashSet(StringComparer.Ordinal);
        var bans = (await db.Bans
                .Where(b => b.Source == source && b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now))
                .ToListAsync(cancellationToken).ConfigureAwait(false))
            .Where(b => !keep.Contains(b.Address))
            .ToList();
        foreach (var ban in bans)
        {
            ban.RemovedUtc = now;
            ban.RemovedBy = removedBy;
            ban.UpdatedUtc = now;
            db.BanEvents.Add(NewEvent(ban, BanEventKinds.Unbanned, removedBy, "no longer on list"));
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return bans.Count;
    }

    public async Task<IReadOnlyList<Ban>> GetActiveAsync(CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = Now;
        return await db.Bans.AsNoTracking()
            .Where(b => b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<Ban?> GetActiveByAddressAsync(string address, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = Now;
        return await db.Bans.AsNoTracking()
            .Where(b => b.Address == address && b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now))
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> CountPriorAsync(string address, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.Bans.CountAsync(b => b.Address == address, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResult<Ban>> QueryAsync(BanQuery query, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = Now;
        IQueryable<Ban> q = db.Bans.AsNoTracking();
        q = query.State.ToLowerInvariant() switch
        {
            "removed" => q.Where(b => b.RemovedUtc != null),
            "expired" => q.Where(b => b.RemovedUtc == null && b.ExpiresUtc != null && b.ExpiresUtc <= now),
            "all" => q,
            _ => q.Where(b => b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now)),
        };

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            string term = query.Search.Trim();
            q = q.Where(b => b.Address.Contains(term) || b.Reason.Contains(term));
        }

        if (!string.IsNullOrEmpty(query.Source))
        {
            q = q.Where(b => b.Source == query.Source);
        }

        if (!string.IsNullOrEmpty(query.RuleId))
        {
            q = q.Where(b => b.RuleId == query.RuleId);
        }

        if (!string.IsNullOrEmpty(query.MachineName))
        {
            q = q.Where(b => b.MachineName == query.MachineName);
        }

        int total = await q.CountAsync(cancellationToken).ConfigureAwait(false);
        var items = await q.OrderByDescending(b => b.CreatedUtc)
            .Skip(Math.Max(0, query.Skip)).Take(Math.Clamp(query.Take, 1, 500))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return new PagedResult<Ban>(items, total);
    }

    public async Task<IReadOnlyList<BanEvent>> GetEventsAsync(int take, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.BanEvents.AsNoTracking().OrderByDescending(e => e.Id)
            .Take(Math.Clamp(take, 1, 1000)).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<BanStats> GetStatsAsync(CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = Now;
        var active = db.Bans.AsNoTracking().Where(b => b.RemovedUtc == null && (b.ExpiresUtc == null || b.ExpiresUtc > now));
        int activeCount = await active.CountAsync(cancellationToken).ConfigureAwait(false);
        int permanent = await active.CountAsync(b => b.ExpiresUtc == null, cancellationToken).ConfigureAwait(false);
        int total = await db.Bans.CountAsync(cancellationToken).ConfigureAwait(false);
        var dayAgo = now.AddHours(-24);
        int last24 = await db.Bans.CountAsync(b => b.CreatedUtc >= dayAgo, cancellationToken).ConfigureAwait(false);

        var weekAgo = now.Date.AddDays(-6);
        var recent = await db.Bans.AsNoTracking().Where(b => b.CreatedUtc >= weekAgo)
            .Select(b => b.CreatedUtc).ToListAsync(cancellationToken).ConfigureAwait(false);
        var perDay = Enumerable.Range(0, 7).Select(i => weekAgo.AddDays(i))
            .Select(day => new DayCount(DateTime.SpecifyKind(day, DateTimeKind.Utc), recent.Count(r => r.Date == day.Date)))
            .ToList();

        var activeRows = await active.Select(b => new { b.RuleId, b.Source, b.Address, b.MachineName, b.Hits })
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var agents = await db.Agents.AsNoTracking().OrderBy(a => a.MachineName).ToListAsync(cancellationToken).ConfigureAwait(false);

        return new BanStats(
            activeCount, total, last24, permanent, perDay,
            Top(activeRows.Select(r => r.RuleId ?? "(none)")),
            Top(activeRows.Select(r => r.Source.StartsWith(BanSources.BlocklistPrefix, StringComparison.Ordinal) ? r.Source : r.Source)),
            activeRows.OrderByDescending(r => r.Hits).Take(10).Select(r => new CountItem(r.Address, r.Hits)).ToList(),
            Top(activeRows.Select(r => string.IsNullOrEmpty(r.MachineName) ? "(unknown)" : r.MachineName)),
            agents);
    }

    public async Task<IReadOnlyList<AllowEntry>> GetAllowlistAsync(CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.Allowlist.AsNoTracking().OrderBy(a => a.Address).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<AllowEntry> AddAllowAsync(AllowEntry entry, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var existing = await db.Allowlist.FirstOrDefaultAsync(a => a.Address == entry.Address, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            existing.Note = entry.Note ?? existing.Note;
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return existing;
        }

        entry.CreatedUtc = entry.CreatedUtc == default ? Now : entry.CreatedUtc;
        db.Allowlist.Add(entry);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return entry;
    }

    public async Task<bool> RemoveAllowAsync(string address, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var existing = await db.Allowlist.FirstOrDefaultAsync(a => a.Address == address, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            return false;
        }

        db.Allowlist.Remove(existing);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    public async Task HeartbeatAsync(AgentInfo agent, CancellationToken cancellationToken)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var existing = await db.Agents.FirstOrDefaultAsync(a => a.MachineName == agent.MachineName, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            db.Agents.Add(agent);
        }
        else
        {
            existing.Os = agent.Os;
            existing.Version = agent.Version;
            existing.Firewall = agent.Firewall;
            existing.AppliedBans = agent.AppliedBans;
            existing.StartedUtc = agent.StartedUtc;
            existing.LastSeenUtc = agent.LastSeenUtc;
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private BanEvent NewEvent(Ban ban, string kind, string? actor, string? detail) => new()
    {
        BanId = ban.Id,
        Address = ban.Address,
        Kind = kind,
        Actor = actor,
        MachineName = _machineName,
        TimestampUtc = Now,
        Detail = detail is { Length: > 512 } ? detail[..512] : detail,
    };

    private static IReadOnlyList<CountItem> Top(IEnumerable<string> keys) =>
        keys.GroupBy(k => k).Select(g => new CountItem(g.Key, g.Count()))
            .OrderByDescending(c => c.Count).ThenBy(c => c.Key).Take(10).ToList();
}
