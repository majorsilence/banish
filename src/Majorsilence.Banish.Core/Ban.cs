namespace Majorsilence.Banish.Core;

/// <summary>Well-known values for <see cref="Ban.Source"/>.</summary>
public static class BanSources
{
    public const string Local = "local";
    public const string Manual = "manual";
    public const string Remote = "remote";
    public const string BlocklistPrefix = "blocklist:";

    public static string Blocklist(string name) => BlocklistPrefix + name;
}

/// <summary>An IP address or CIDR range that is (or was) blocked.</summary>
public sealed class Ban
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Normalized IP address or CIDR (see <see cref="IpAddressUtil"/>).</summary>
    public string Address { get; set; } = "";

    public string Reason { get; set; } = "";
    public string Source { get; set; } = BanSources.Local;
    public string? RuleId { get; set; }
    public DateTime CreatedUtc { get; set; }
    public DateTime UpdatedUtc { get; set; }

    /// <summary>When the ban lapses; <c>null</c> means permanent.</summary>
    public DateTime? ExpiresUtc { get; set; }

    /// <summary>Set when the ban was lifted by hand (unban) or replaced by a blocklist refresh.</summary>
    public DateTime? RemovedUtc { get; set; }

    public string? RemovedBy { get; set; }
    public string MachineName { get; set; } = "";
    public string? CreatedBy { get; set; }

    /// <summary>Number of failures that led to this ban (or were added to it).</summary>
    public int Hits { get; set; }

    public bool IsActive(DateTime nowUtc) =>
        RemovedUtc is null && (ExpiresUtc is null || ExpiresUtc > nowUtc);
}

public sealed class BanEvent
{
    public long Id { get; set; }
    public Guid BanId { get; set; }
    public string Address { get; set; } = "";
    public string Kind { get; set; } = "";
    public string? Actor { get; set; }
    public string MachineName { get; set; } = "";
    public DateTime TimestampUtc { get; set; }
    public string? Detail { get; set; }
}

public static class BanEventKinds
{
    public const string Banned = "banned";
    public const string Extended = "extended";
    public const string Unbanned = "unbanned";
}

public sealed class AllowEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Address { get; set; } = "";
    public string? Note { get; set; }
    public DateTime CreatedUtc { get; set; }
    public string? CreatedBy { get; set; }
}

public sealed class AgentInfo
{
    public string MachineName { get; set; } = "";
    public string Os { get; set; } = "";
    public string Version { get; set; } = "";
    public string Firewall { get; set; } = "";
    public int AppliedBans { get; set; }
    public DateTime StartedUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
}

public sealed record FailureEvent(System.Net.IPAddress Address, string RuleName, DateTime TimestampUtc, string? Line = null);

/// <summary>Roles carried by API keys and dashboard users.</summary>
public static class ApiRoles
{
    /// <summary>An agent: may read active bans, report bans of its own and send heartbeats.</summary>
    public const string Agent = "agent";

    /// <summary>Full control: ban, unban, allow-list, sync, key management.</summary>
    public const string Admin = "admin";

    /// <summary>Read-only access to statistics and ban lists (dashboard users).</summary>
    public const string Viewer = "viewer";
}

/// <summary>JSON settings shared by the Web API and its client so both ends agree.</summary>
public static class BanishJson
{
    public static readonly System.Text.Json.JsonSerializerOptions Options = new(System.Text.Json.JsonSerializerDefaults.Web);
}
