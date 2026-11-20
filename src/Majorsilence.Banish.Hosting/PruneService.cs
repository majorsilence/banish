using Majorsilence.Banish.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Hosting;

/// <summary>Deletes ban history and events older than <see cref="RetentionOptions"/>, once at start-up and then every interval.</summary>
public sealed class PruneService : BackgroundService
{
    private readonly IPrunable _store;
    private readonly RetentionOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<PruneService> _logger;

    public PruneService(IPrunable store, BanishOptions options, ILogger<PruneService> logger, TimeProvider? time = null)
    {
        _store = store;
        _options = options.Retention;
        _logger = logger;
        _time = time ?? TimeProvider.System;
    }

    public static (DateTime? Bans, DateTime? Events) Cutoffs(RetentionOptions options, DateTime nowUtc) =>
        (options.BanHistoryDays > 0 ? nowUtc.AddDays(-options.BanHistoryDays) : null,
         options.EventDays > 0 ? nowUtc.AddDays(-options.EventDays) : null);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var every = TimeSpan.FromHours(Math.Max(1, _options.IntervalHours));
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken).ConfigureAwait(false);
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var (bans, events) = Cutoffs(_options, _time.GetUtcNow().UtcDateTime);
                    var result = await _store.PruneAsync(bans, events, dryRun: false, stoppingToken).ConfigureAwait(false);
                    if (result.Bans > 0 || result.Events > 0)
                    {
                        _logger.LogInformation("Retention: deleted {Bans} old bans and {Events} old events", result.Bans, result.Events);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Retention pass failed; will try again in {Hours} h", every.TotalHours);
                }

                await Task.Delay(every, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }
}

public static class RetentionRegistration
{
    /// <summary>Adds the background pass when retention is enabled and this process owns the data (an EF store).</summary>
    public static IServiceCollection AddBanishRetention(this IServiceCollection services, BanishOptions options)
    {
        if (options.Retention.Enabled && Store.Ef.EfStoreRegistration.IsEfProvider(options.Store.Provider))
        {
            services.AddSingleton<IPrunable>(sp => (IPrunable)sp.GetRequiredService<IBanStore>());
            services.AddHostedService<PruneService>();
        }

        return services;
    }
}
