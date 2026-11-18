using Majorsilence.Banish.Core;
using Majorsilence.Banish.Detectors;
using Majorsilence.Banish.Store.Ef;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Hosting;

/// <summary>Creates the database schema before anything else uses it.</summary>
public sealed class StoreInitializer : IHostedLifecycleService
{
    private readonly IBanStore _store;
    private readonly ILogger<StoreInitializer> _logger;

    public StoreInitializer(IBanStore store, ILogger<StoreInitializer> logger)
    {
        _store = store;
        _logger = logger;
    }

    public async Task StartingAsync(CancellationToken cancellationToken)
    {
        if (_store is not EfBanStore ef)
        {
            return;
        }

        // Several agents may start at once against a shared database; retry a few times.
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                await ef.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (attempt < 5 && ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Could not prepare the store (attempt {Attempt}); retrying", attempt);
                await Task.Delay(TimeSpan.FromSeconds(2 * attempt), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>Runs one detector per enabled rule and feeds failures to the ban engine.</summary>
public sealed class DetectorService : BackgroundService
{
    private readonly BanishOptions _options;
    private readonly BanEngine _engine;
    private readonly ILoggerFactory _loggers;

    public DetectorService(BanishOptions options, BanEngine engine, ILoggerFactory loggers)
    {
        _options = options;
        _engine = engine;
        _loggers = loggers;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var logger = _loggers.CreateLogger("Detectors");
        var tasks = new List<Task>();
        foreach (var rule in _options.Rules ?? [])
        {
            if (!rule.Enabled)
            {
                continue;
            }

            var detector = DetectorFactory.Create(rule, logger);
            if (detector is null)
            {
                continue;
            }

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    await detector.RunAsync(OnFailureAsync, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Detector for rule {Rule} stopped", rule.Name);
                }
            }, stoppingToken));
        }

        logger.LogInformation("Started {Count} detector(s)", tasks.Count);
        await Task.WhenAll(tasks).ConfigureAwait(false);

        async ValueTask OnFailureAsync(FailureEvent failure)
        {
            try
            {
                await _engine.ReportFailureAsync(failure, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Could not record failure from {Address}", failure.Address);
            }
        }
    }
}

/// <summary>Periodically syncs the firewall with the store, refreshes the allow-list and sends heartbeats.</summary>
public sealed class ReconcileService : BackgroundService
{
    private readonly BanishOptions _options;
    private readonly IBanStore _store;
    private readonly IFirewall _firewall;
    private readonly FirewallReconciler _reconciler;
    private readonly AllowlistProvider _allowlist;
    private readonly ILogger<ReconcileService> _logger;
    private readonly DateTime _started = DateTime.UtcNow;

    public ReconcileService(
        BanishOptions options,
        IBanStore store,
        IFirewall firewall,
        FirewallReconciler reconciler,
        AllowlistProvider allowlist,
        ILogger<ReconcileService> logger)
    {
        _options = options;
        _store = store;
        _firewall = firewall;
        _reconciler = reconciler;
        _allowlist = allowlist;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(2, _options.Reconcile.IntervalSeconds));
        _logger.LogInformation("Firewall provider: {Firewall}; reconciling every {Interval}", _firewall.Name, interval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _allowlist.RefreshAsync(_store, stoppingToken).ConfigureAwait(false);
                await _reconciler.ReconcileAsync(stoppingToken).ConfigureAwait(false);
                await _store.HeartbeatAsync(new AgentInfo
                {
                    MachineName = _options.MachineName,
                    Os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                    Version = typeof(ReconcileService).Assembly.GetName().Version?.ToString(3) ?? "",
                    Firewall = _firewall.Name,
                    AppliedBans = _reconciler.AppliedCount,
                    StartedUtc = _started,
                    LastSeenUtc = DateTime.UtcNow,
                }, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Reconcile failed; will retry");
            }

            try
            {
                await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
