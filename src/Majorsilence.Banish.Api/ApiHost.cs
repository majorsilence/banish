using Majorsilence.Banish.Core;
using Majorsilence.Banish.Dashboard;
using Majorsilence.Banish.Hosting;
using Majorsilence.Banish.Store.Ef;
using Majorsilence.Banish.Sync;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
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

        if (options.Auth.Mode.Equals(AuthModes.Oidc, StringComparison.OrdinalIgnoreCase)
            && (string.IsNullOrWhiteSpace(options.Auth.Oidc.Authority) || string.IsNullOrWhiteSpace(options.Auth.Oidc.ClientId)))
        {
            throw new InvalidOperationException("Auth:Mode is Oidc, so Auth:Oidc:Authority and Auth:Oidc:ClientId are required.");
        }

        var builder = WebApplication.CreateBuilder(args);
        builder.WebHost.UseStaticWebAssets();
        builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
        builder.WebHost.UseUrls(options.Api.Urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        var services = builder.Services;
        // Keep the keys that protect sign-in cookies and antiforgery tokens with the data, so a restart
        // (or a new container) does not sign everyone out. Falls back to the framework default if the
        // directory cannot be created or written.
        string keyDirectory = options.Api.KeyDirectory ?? Path.Combine(EfStoreRegistration.DefaultDataDirectory(), "keys");
        if (TryPrepareDirectory(keyDirectory))
        {
            services.AddDataProtection().SetApplicationName("Banish").PersistKeysToFileSystem(new DirectoryInfo(keyDirectory));
        }

        services.AddWindowsService(o => o.ServiceName = "BanishApi");
        services.AddSystemd();
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
        services.AddBanishSync(options, runInBackground: true);
        services.AddHostedService<StoreInitializer>();

        bool oidc = options.Auth.Mode.Equals(AuthModes.Oidc, StringComparison.OrdinalIgnoreCase);
        ApiAuth.Configure(services, options, oidc);
        services.AddBanishDashboard();

        services.AddRateLimiter(o =>
        {
            o.AddPolicy(DashboardSetup.LoginRateLimitPolicy, ctx =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
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
        app.UseAntiforgery();
        ApiEndpoints.Map(app);
        // The manifest is named after the API assembly (not the entry assembly, which differs when hosted by a test runner).
        string manifest = Path.Combine(AppContext.BaseDirectory, typeof(ApiHost).Assembly.GetName().Name + ".staticwebassets.endpoints.json");
        if (File.Exists(manifest))
        {
            app.MapStaticAssets(manifest);
        }
        else
        {
            app.Logger.LogWarning("Static asset manifest {Manifest} not found; the interactive dashboard cannot load its script.", manifest);
        }

        app.MapBanishDashboard(options);

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

    private static bool TryPrepareDirectory(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            string probe = Path.Combine(directory, ".write-test");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
