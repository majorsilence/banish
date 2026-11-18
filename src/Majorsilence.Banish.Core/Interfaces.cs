namespace Majorsilence.Banish.Core;

/// <summary>Source of failure events (log tail, event log, command output...).</summary>
public interface IDetector
{
    string Name { get; }

    /// <summary>Runs until cancelled, calling <paramref name="onFailure"/> for each failure seen.</summary>
    Task RunAsync(Func<FailureEvent, ValueTask> onFailure, CancellationToken cancellationToken);
}

/// <summary>Applies a set of blocked addresses to the host firewall.</summary>
public interface IFirewall
{
    string Name { get; }

    /// <summary>Makes the firewall block exactly <paramref name="addresses"/> (normalized IPs/CIDRs).</summary>
    Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken);

    /// <summary>Removes everything this firewall provider added.</summary>
    Task ClearAsync(CancellationToken cancellationToken);
}

public sealed record BanQuery
{
    public string? Search { get; init; }
    public string? Source { get; init; }
    public string? RuleId { get; init; }
    public string? MachineName { get; init; }

    /// <summary>active (default), removed, expired or all.</summary>
    public string State { get; init; } = "active";

    public int Skip { get; init; }
    public int Take { get; init; } = 50;
}

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total);

public sealed record CountItem(string Key, int Count);

public sealed record DayCount(DateTime DayUtc, int Count);

public sealed record BanStats(
    int ActiveBans,
    int TotalBans,
    int BansLast24Hours,
    int PermanentBans,
    IReadOnlyList<DayCount> BansPerDay,
    IReadOnlyList<CountItem> TopRules,
    IReadOnlyList<CountItem> TopSources,
    IReadOnlyList<CountItem> TopAddresses,
    IReadOnlyList<CountItem> ByMachine,
    IReadOnlyList<AgentInfo> Agents);

/// <summary>
/// Central record of bans. The same contract is implemented over a local SQLite file, any EF Core
/// provider, or the Banish Web API.
/// </summary>
public interface IBanStore
{
    /// <summary>
    /// Adds a ban. If an active ban for the same address exists it is extended instead and returned.
    /// </summary>
    Task<Ban> AddAsync(Ban ban, CancellationToken cancellationToken);

    /// <summary>Lifts every active ban for an address or CIDR. Returns the number lifted.</summary>
    Task<int> RemoveAsync(string address, string removedBy, CancellationToken cancellationToken);

    /// <summary>Lifts all active bans of a source (used by blocklist refresh). Returns the number lifted.</summary>
    Task<int> RemoveBySourceAsync(string source, IReadOnlyCollection<string> except, string removedBy, CancellationToken cancellationToken);

    Task<IReadOnlyList<Ban>> GetActiveAsync(CancellationToken cancellationToken);

    Task<Ban?> GetActiveByAddressAsync(string address, CancellationToken cancellationToken);

    /// <summary>How many bans (of any state) exist for an address; drives escalation.</summary>
    Task<int> CountPriorAsync(string address, CancellationToken cancellationToken);

    Task<PagedResult<Ban>> QueryAsync(BanQuery query, CancellationToken cancellationToken);

    Task<IReadOnlyList<BanEvent>> GetEventsAsync(int take, CancellationToken cancellationToken);

    Task<BanStats> GetStatsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<AllowEntry>> GetAllowlistAsync(CancellationToken cancellationToken);

    Task<AllowEntry> AddAllowAsync(AllowEntry entry, CancellationToken cancellationToken);

    Task<bool> RemoveAllowAsync(string address, CancellationToken cancellationToken);

    Task HeartbeatAsync(AgentInfo agent, CancellationToken cancellationToken);
}
