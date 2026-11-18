using Majorsilence.Banish.Core;
using Majorsilence.Banish.Firewall;
using Majorsilence.Banish.Store.Api;
using Majorsilence.Banish.Store.Ef;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Hosting;

public static class BanishServices
{
    /// <summary>Registers the ban store selected by <c>Store:Provider</c>.</summary>
    public static IServiceCollection AddBanishStore(this IServiceCollection services, BanishOptions options)
    {
        services.AddSingleton(options);
        if (EfStoreRegistration.IsEfProvider(options.Store.Provider))
        {
            services.AddBanishEfStore(options.Store, options.MachineName);
        }
        else if (options.Store.Provider.Equals(StoreProviders.Api, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(options.Store.ApiUrl) || string.IsNullOrWhiteSpace(options.Store.ApiKey))
            {
                throw new InvalidOperationException("Store:ApiUrl and Store:ApiKey are required when Store:Provider is Api.");
            }

            services.AddSingleton<IBanStore>(_ => new HttpBanStore(new HttpClient(), options.Store.ApiUrl, options.Store.ApiKey));
        }
        else
        {
            throw new NotSupportedException($"Store provider '{options.Store.Provider}' is not supported.");
        }

        return services;
    }

    /// <summary>Registers everything the agent needs on top of the store.</summary>
    public static IServiceCollection AddBanishAgent(this IServiceCollection services, BanishOptions options)
    {
        services.AddBanishStore(options);
        services.AddSingleton<IProcessRunner, ProcessRunner>();
        services.AddSingleton(new AllowlistProvider(options.Allowlist));
        services.AddSingleton<IFirewall>(sp => FirewallFactory.Create(
            options.Firewall.Provider,
            sp.GetRequiredService<IProcessRunner>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("Firewall")));
        services.AddSingleton(sp => new BanEngine(
            sp.GetRequiredService<IBanStore>(),
            options.Rules ?? [],
            () => sp.GetRequiredService<AllowlistProvider>().Current,
            options.MachineName,
            logger: sp.GetRequiredService<ILoggerFactory>().CreateLogger("Engine")));
        services.AddSingleton(sp => new FirewallReconciler(
            sp.GetRequiredService<IBanStore>(),
            sp.GetRequiredService<IFirewall>(),
            () => sp.GetRequiredService<AllowlistProvider>().Current,
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("Reconciler")));
        services.AddHostedService<StoreInitializer>();
        services.AddHostedService<DetectorService>();
        services.AddHostedService<ReconcileService>();
        return services;
    }
}
