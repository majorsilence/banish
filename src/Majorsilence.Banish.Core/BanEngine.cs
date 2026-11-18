using System.Net;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Core;

/// <summary>
/// Counts failures per (rule, address) in a sliding window and creates bans when a rule's
/// threshold is crossed. Allow-listed addresses are never banned.
/// </summary>
public sealed class BanEngine
{
    private readonly IBanStore _store;
    private readonly IReadOnlyDictionary<string, RuleOptions> _rules;
    private readonly string _machineName;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Func<Allowlist> _allowlist;
    private readonly Dictionary<(string Rule, string Ip), Queue<DateTime>> _windows = [];
    private readonly object _gate = new();
    private int _sinceSweep;

    public BanEngine(
        IBanStore store,
        IEnumerable<RuleOptions> rules,
        Func<Allowlist> allowlist,
        string machineName,
        TimeProvider? time = null,
        ILogger? logger = null)
    {
        _store = store;
        _rules = rules.ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);
        _allowlist = allowlist;
        _machineName = machineName;
        _time = time ?? TimeProvider.System;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    /// <summary>Records a failure; returns the ban if this failure triggered one.</summary>
    public async Task<Ban?> ReportFailureAsync(FailureEvent failure, CancellationToken cancellationToken)
    {
        if (!_rules.TryGetValue(failure.RuleName, out var rule) || !rule.Enabled)
        {
            return null;
        }

        var address = failure.Address;
        if (!IpAddressUtil.IsBannable(address) || _allowlist().Contains(address))
        {
            return null;
        }

        var now = _time.GetUtcNow().UtcDateTime;
        string key = address.ToString();
        int count;
        lock (_gate)
        {
            if (!_windows.TryGetValue((rule.Name, key), out var queue))
            {
                queue = new Queue<DateTime>();
                _windows[(rule.Name, key)] = queue;
            }

            var cutoff = now - TimeSpan.FromSeconds(rule.FindTimeSeconds);
            while (queue.Count > 0 && queue.Peek() < cutoff)
            {
                queue.Dequeue();
            }

            queue.Enqueue(now);
            count = queue.Count;
            if (++_sinceSweep >= 5000)
            {
                _sinceSweep = 0;
                Sweep(now);
            }
        }

        if (count < rule.MaxRetry)
        {
            return null;
        }

        lock (_gate)
        {
            _windows.Remove((rule.Name, key));
        }

        return await BanAsync(address, rule, count, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Ban?> BanAsync(IPAddress address, RuleOptions rule, int hits, CancellationToken ct)
    {
        string normalized = address.ToString();
        var existing = await _store.GetActiveByAddressAsync(normalized, ct).ConfigureAwait(false);
        if (existing is not null)
        {
            return null;
        }

        int prior = await _store.CountPriorAsync(normalized, ct).ConfigureAwait(false);
        var now = _time.GetUtcNow().UtcDateTime;
        var duration = Escalation.DurationFor(rule.BanMinutes, prior);
        var ban = new Ban
        {
            Address = normalized,
            Reason = $"{hits} failures in {rule.FindTimeSeconds}s ({rule.Name})",
            Source = BanSources.Local,
            RuleId = rule.Name,
            CreatedUtc = now,
            UpdatedUtc = now,
            ExpiresUtc = duration is null ? null : now + duration,
            MachineName = _machineName,
            CreatedBy = "banish",
            Hits = hits,
        };

        var saved = await _store.AddAsync(ban, ct).ConfigureAwait(false);
        _logger.LogWarning(
            "Banned {Address} by rule {Rule} ({Hits} failures); {Expiry}",
            normalized, rule.Name, hits, duration is null ? "permanent" : $"for {duration}");
        return saved;
    }

    private void Sweep(DateTime now)
    {
        foreach (var (key, queue) in _windows.ToList())
        {
            var window = _rules.TryGetValue(key.Rule, out var rule) ? rule.FindTimeSeconds : 600;
            if (queue.Count == 0 || queue.Peek() < now - TimeSpan.FromSeconds(window))
            {
                _windows.Remove(key);
            }
        }
    }
}

public static class Escalation
{
    /// <summary>Ban length for the (prior+1)th ban of an address; <c>null</c> is permanent.</summary>
    public static readonly long[] DefaultLadder = [10, 60, 1440, 10080];

    public static TimeSpan? DurationFor(IReadOnlyList<long> banMinutes, int priorBans)
    {
        if (banMinutes.Count == 0)
        {
            banMinutes = DefaultLadder;
        }

        long minutes = banMinutes[Math.Min(priorBans, banMinutes.Count - 1)];
        return minutes <= 0 ? null : TimeSpan.FromMinutes(minutes);
    }
}
