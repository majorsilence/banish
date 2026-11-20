using Majorsilence.Banish.Store.Ef;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Majorsilence.Banish.Dashboard;

/// <summary>
/// Tells open dashboard pages that something changed so they reload straight away instead of waiting for the
/// next poll. Bursts (a blocklist import writes in bulk) are merged into one notification.
/// </summary>
public sealed class ChangeFeed : IDisposable
{
    private readonly TimeSpan _delay;
    private readonly object _gate = new();
    private Timer? _timer;

    public ChangeFeed(TimeSpan? delay = null) => _delay = delay ?? TimeSpan.FromMilliseconds(400);

    /// <summary>Raised on a thread-pool thread; subscribers must marshal to their own context.</summary>
    public event Action? Changed;

    public void Notify()
    {
        lock (_gate)
        {
            _timer ??= new Timer(_ =>
            {
                lock (_gate)
                {
                    _timer?.Dispose();
                    _timer = null;
                }

                Changed?.Invoke();
            }, null, _delay, Timeout.InfiniteTimeSpan);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _timer?.Dispose();
            _timer = null;
        }
    }
}

/// <summary>Connects the in-process EF store to the <see cref="ChangeFeed"/>.</summary>
internal sealed class ChangeFeedBridge(IServiceProvider services, ChangeFeed feed) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Bans added through the Web API, the dashboard or a blocklist refresh all go through this store.
        services.GetService<EfBanStore>()?.Changed += feed.Notify;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        services.GetService<EfBanStore>()?.Changed -= feed.Notify;
        return Task.CompletedTask;
    }
}
