using Majorsilence.Banish.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Sync;

/// <summary>Runs each enabled source at its own interval, starting shortly after startup.</summary>
public sealed class SyncService : BackgroundService
{
    private readonly BlocklistSyncer _syncer;
    private readonly BanishOptions _options;
    private readonly ILogger<SyncService> _logger;

    public SyncService(BlocklistSyncer syncer, BanishOptions options, ILogger<SyncService> logger)
    {
        _syncer = syncer;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var due = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken).ConfigureAwait(false);
            while (!stoppingToken.IsCancellationRequested)
            {
                foreach (var source in _options.Sync.Sources.Where(s => s.Enabled))
                {
                    if (due.TryGetValue(source.Name, out var at) && at > DateTime.UtcNow)
                    {
                        continue;
                    }

                    try
                    {
                        await _syncer.SyncAsync(source, dryRun: false, stoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.LogError(ex, "Blocklist {Source} failed", source.Name);
                    }

                    // A failed or refused refresh is retried at the normal interval, never in a tight loop.
                    due[source.Name] = DateTime.UtcNow.AddMinutes(Math.Max(5, source.IntervalMinutes));
                }

                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }
}

public static class SyncRegistration
{
    public static IServiceCollection AddBanishSync(this IServiceCollection services, BanishOptions options, bool runInBackground)
    {
        services.AddSingleton(sp => new BlocklistSyncer(
            sp.GetRequiredService<IBanStore>(),
            options,
            sp.GetRequiredService<AllowlistProvider>(),
            new HttpClient(new SocketsHttpHandler { MaxAutomaticRedirections = 3, ConnectTimeout = TimeSpan.FromSeconds(15) }) { Timeout = TimeSpan.FromMinutes(2) },
            logger: sp.GetRequiredService<ILoggerFactory>().CreateLogger("Sync")));
        services.AddSingleton<IBlocklistSync>(sp => sp.GetRequiredService<BlocklistSyncer>());
        if (runInBackground && options.Sync.Sources.Any(s => s.Enabled))
        {
            services.AddHostedService<SyncService>();
        }

        return services;
    }
}
