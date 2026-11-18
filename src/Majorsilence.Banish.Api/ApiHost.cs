using Majorsilence.Banish.Core;
using Majorsilence.Banish.Hosting;
using Majorsilence.Banish.Store.Ef;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.RateLimiting;

namespace Majorsilence.Banish.Api;

/// <summary>Builds the Banish Web API host: the central ban registry.</summary>
public static class ApiHost
{
    public static WebApplication Build(BanishOptions options, string[] args)
    {
        if (!EfStoreRegistration.IsEfProvider(options.Store.Provider))
        {
            throw new InvalidOperationException(
                "The Web API keeps the central registry, so Store:Provider must be Sqlite, PostgreSql, SqlServer or MySql (not Api).");
        }

        var builder = WebApplication.CreateBuilder(args);
        builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
        builder.WebHost.UseUrls(options.Api.Urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        var services = builder.Services;
        services.AddBanishStore(options);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(new AllowlistProvider(options.Allowlist));
        // Only rules with the Http detector are fed by the API (POST /api/v1/failures).
        var httpRules = (options.Rules ?? []).Where(r => r.Detector.Equals("Http", StringComparison.OrdinalIgnoreCase)).ToList();
        services.AddSingleton(sp => new BanEngine(
            sp.GetRequiredService<IBanStore>(),
            httpRules,
            () => sp.GetRequiredService<AllowlistProvider>().Current,
            options.MachineName,
            logger: sp.GetRequiredService<ILoggerFactory>().CreateLogger("Engine")));
        services.AddHostedService<StoreInitializer>();

        services.AddAuthentication(ApiKeyDefaults.Scheme)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyDefaults.Scheme, _ => { });
        services.AddAuthorizationBuilder()
            .AddPolicy(Policies.Agent, p => p.RequireRole(ApiRoles.Agent, ApiRoles.Admin))
            .AddPolicy(Policies.Admin, p => p.RequireRole(ApiRoles.Admin))
            .AddPolicy(Policies.Viewer, p => p.RequireAssertion(ctx =>
                options.Dashboard.PublicReadOnly || ctx.User.Identity?.IsAuthenticated == true));

        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions { PermitLimit = 600, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
        });
        services.ConfigureHttpJsonOptions(o =>
        {
            o.SerializerOptions.PropertyNamingPolicy = BanishJson.Options.PropertyNamingPolicy;
            o.SerializerOptions.PropertyNameCaseInsensitive = true;
        });

        var app = builder.Build();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        ApiEndpoints.Map(app);

        foreach (string url in options.Api.Urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                && !url.Contains("127.0.0.1") && !url.Contains("localhost") && !url.Contains("[::1]"))
            {
                app.Logger.LogWarning("Listening on {Url} without TLS. API keys and admin credentials would cross the network in clear text; put the API behind HTTPS.", url);
            }
        }

        return app;
    }
}
