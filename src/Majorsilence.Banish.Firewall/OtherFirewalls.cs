using Microsoft.Extensions.Logging;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Firewall;

/// <summary>Logs what would be blocked without touching the firewall (dry-run).</summary>
public sealed class DryRunFirewall : IFirewall
{
    private readonly ILogger _logger;

    public DryRunFirewall(ILogger logger) => _logger = logger;

    public string Name => "dry-run";

    public Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken)
    {
        _logger.LogInformation("[dry-run] would block {Count} addresses: {Addresses}", addresses.Count, string.Join(", ", addresses.Take(20)));
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>Does nothing; for hosts where only the shared list is wanted (dashboard-only agents).</summary>
public sealed class NullFirewall : IFirewall
{
    public string Name => "none";

    public Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
