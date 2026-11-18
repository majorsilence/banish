namespace Majorsilence.Banish.Core;

/// <summary>Root of <c>banish.json</c>.</summary>
public sealed class BanishOptions
{
    public string MachineName { get; set; } = Environment.MachineName;
    public StoreOptions Store { get; set; } = new();
    public List<RuleOptions>? Rules { get; set; }
    public AllowlistOptions Allowlist { get; set; } = new();
    public FirewallOptions Firewall { get; set; } = new();
    public ReconcileOptions Reconcile { get; set; } = new();
    public SyncOptions Sync { get; set; } = new();
    public ApiOptions Api { get; set; } = new();
    public DashboardOptions Dashboard { get; set; } = new();
    public AuthOptions Auth { get; set; } = new();
}

public static class AuthModes
{
    public const string Local = "Local";
    public const string Oidc = "Oidc";
}

public sealed class AuthOptions
{
    /// <summary>Local (default; accounts kept in the store) or Oidc (an external OpenID Connect provider). One mode is active at a time.</summary>
    public string Mode { get; set; } = AuthModes.Local;

    public OidcOptions Oidc { get; set; } = new();
}

public sealed class OidcOptions
{
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }

    /// <summary>Extra scopes; <c>openid</c> and <c>profile</c> are always requested.</summary>
    public List<string> Scopes { get; set; } = [];

    /// <summary>Claim holding the user's roles or groups.</summary>
    public string RoleClaim { get; set; } = "roles";

    /// <summary>Values of <see cref="RoleClaim"/> that grant the Admin role.</summary>
    public List<string> AdminRoles { get; set; } = [];

    /// <summary>Values of <see cref="RoleClaim"/> that grant read-only access.</summary>
    public List<string> ViewerRoles { get; set; } = [];

    public bool RequireHttpsMetadata { get; set; } = true;
}

public sealed class DashboardOptions
{
    /// <summary>When true, anyone can open the read-only statistics views without signing in.</summary>
    public bool PublicReadOnly { get; set; }

    /// <summary>Hide the last part of each IP address from viewers who are not admins.</summary>
    public bool MaskIps { get; set; } = true;
}

public static class StoreProviders
{
    public const string Sqlite = "Sqlite";
    public const string PostgreSql = "PostgreSql";
    public const string SqlServer = "SqlServer";
    public const string MySql = "MySql";
    public const string Api = "Api";
}

public sealed class StoreOptions
{
    /// <summary>Sqlite (default), PostgreSql, SqlServer, MySql or Api.</summary>
    public string Provider { get; set; } = StoreProviders.Sqlite;

    /// <summary>Connection string; for Sqlite it defaults to a file in the data directory.</summary>
    public string? ConnectionString { get; set; }

    /// <summary>Base URL of the Banish Web API when <see cref="Provider"/> is Api.</summary>
    public string? ApiUrl { get; set; }

    /// <summary>Per-agent API key when <see cref="Provider"/> is Api.</summary>
    public string? ApiKey { get; set; }
}

public sealed class AllowlistOptions
{
    public List<string> Entries { get; set; } = [];
    public bool IncludePrivateRanges { get; set; } = true;
}

public sealed class FirewallOptions
{
    /// <summary>Auto, Nftables, IpTables, Windows, Pf, DryRun or None.</summary>
    public string Provider { get; set; } = "Auto";
}

public sealed class ReconcileOptions
{
    public int IntervalSeconds { get; set; } = 15;
}

public sealed class ApiOptions
{
    /// <summary>Listen URLs of the Web API host.</summary>
    public string Urls { get; set; } = "http://127.0.0.1:5380";

    /// <summary>Where sign-in cookie and antiforgery keys are kept; defaults to <c>keys</c> inside the data directory.</summary>
    public string? KeyDirectory { get; set; }
}

public sealed class SyncOptions
{
    public List<BlocklistSourceOptions> Sources { get; set; } = [];
}

public sealed class BlocklistSourceOptions
{
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// plain (first token of each line; # and ; start comments), csv (first column), or json (an array
    /// or one-per-line values, each a string or an object with a cidr/ip/address field).
    /// </summary>
    public string Format { get; set; } = "plain";

    public int IntervalMinutes { get; set; } = 360;
    public int MaxEntries { get; set; } = 200_000;

    /// <summary>
    /// A refresh that would drop more than this share of the source's current entries (once there are
    /// at least 100) is refused, so a truncated download cannot wipe the list.
    /// </summary>
    public int MaxRemovalPercent { get; set; } = 50;
    public bool AllowInsecureHttp { get; set; }
    public Dictionary<string, string> Headers { get; set; } = [];
}

/// <summary>A jail: what to watch, what counts as a failure, and how long to ban.</summary>
public sealed class RuleOptions
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;

    /// <summary>LogFile, Command or WindowsEventLog.</summary>
    public string Detector { get; set; } = "LogFile";

    /// <summary>LogFile: files to tail; the file name part may contain * and ? wildcards.</summary>
    public List<string> Paths { get; set; } = [];

    /// <summary>Command: program and arguments whose standard output is read line by line.</summary>
    public List<string> Command { get; set; } = [];

    /// <summary>WindowsEventLog: log name, e.g. Security.</summary>
    public string? EventLog { get; set; }

    /// <summary>WindowsEventLog: XPath query, e.g. <c>*[System[(EventID=4625)]]</c>.</summary>
    public string? EventQuery { get; set; }

    /// <summary>Regexes with a named group <c>ip</c>.</summary>
    public List<string> Patterns { get; set; } = [];

    /// <summary>Lines matching any of these are skipped.</summary>
    public List<string> IgnorePatterns { get; set; } = [];

    public int MaxRetry { get; set; } = 5;
    public int FindTimeSeconds { get; set; } = 600;

    /// <summary>
    /// Ban length in minutes for the 1st, 2nd, ... ban of the same address; the last entry repeats;
    /// 0 is permanent. Empty means the default ladder (10 min, 1 h, 1 day, 7 days).
    /// </summary>
    public List<long> BanMinutes { get; set; } = [];

    /// <summary>Read the whole file from the start instead of only new lines (LogFile).</summary>
    public bool ReadFromStart { get; set; }
}
