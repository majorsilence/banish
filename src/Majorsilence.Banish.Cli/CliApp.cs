using System.Text;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Hosting;
using Majorsilence.Banish.Store.Ef;
using Microsoft.Extensions.DependencyInjection;

namespace Majorsilence.Banish.Cli;

/// <summary>The <c>banish</c> command line.</summary>
public static class CliApp
{
    private const string Usage = """
        banish - manage banned IP addresses

        Usage: banish [--config <file>] <command> [options]

        Commands:
          status                          Show store, counts and agents
          list [--all|--removed|--expired] [--search <text>] [--take <n>]
                                          List bans (active by default)
          ban <ip|cidr> [--reason <text>] [--for <30m|2h|7d|permanent>] [--force]
                                          Ban an address by hand (default: permanent)
          unban <ip|cidr>                 Lift a ban
          allow list | add <ip|cidr> [--note <text>] | remove <ip|cidr>
                                          Manage the shared allow-list
          test-rule <rule> <logfile>      Show what a rule would match in a log file
          user create <name> [--role admin|viewer] [--password-stdin] | list | passwd <name> [--password-stdin] | delete <name>
                                          Manage local dashboard accounts (run where the central database is reachable)
          apikey create <name> [--role agent|admin] | list | revoke <name>
                                          Manage Web API keys (run where the central database is reachable)
          sync [--dry-run]                Refresh blocklists now
          config path | show | init [--force]
                                          Show the configuration file location / effective settings / write a sample
          install [--api] [--config <file>] [--no-start]
                                          Register the agent (or, with --api, the API and dashboard) as a service
          uninstall [--api]               Remove the service
          help                            Show this help
        """;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        var parsed = ParsedArgs.Parse(args);
        string? command = parsed.Positional.FirstOrDefault();
        if (command is null or "help" or "--help" or "-h")
        {
            await output.WriteLineAsync(Usage).ConfigureAwait(false);
            return command is null ? 1 : 0;
        }

        BanishOptions options;
        try
        {
            options = BanishConfig.Load(parsed.Option("config"));
        }
        catch (Exception ex)
        {
            await error.WriteLineAsync($"Could not read configuration: {ex.Message}").ConfigureAwait(false);
            return 2;
        }

        try
        {
            switch (command)
            {
                case "config":
                    return await ConfigAsync(parsed, options, output).ConfigureAwait(false);
                case "test-rule":
                    return await TestRuleAsync(parsed, options, output, error).ConfigureAwait(false);
                case "install":
                case "uninstall":
                    return await ServiceCommandAsync(command, parsed, output, error, cancellationToken).ConfigureAwait(false);
            }

            await using var provider = new ServiceCollection().AddBanishStore(options).BuildServiceProvider();
            var store = provider.GetRequiredService<IBanStore>();
            if (store is EfBanStore ef)
            {
                await ef.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
            }

            return command switch
            {
                "status" => await StatusAsync(store, options, output, cancellationToken).ConfigureAwait(false),
                "list" => await ListAsync(store, parsed, output, cancellationToken).ConfigureAwait(false),
                "ban" => await BanAsync(store, options, parsed, output, error, cancellationToken).ConfigureAwait(false),
                "unban" => await UnbanAsync(store, parsed, output, error, cancellationToken).ConfigureAwait(false),
                "allow" => await AllowAsync(store, parsed, output, error, cancellationToken).ConfigureAwait(false),
                "user" => await UserAsync(provider, parsed, output, error, cancellationToken).ConfigureAwait(false),
                "apikey" => await ApiKeyAsync(provider, parsed, output, error, cancellationToken).ConfigureAwait(false),
                "sync" => await SyncCommand.RunAsync(options, parsed.Flag("dry-run"), output, error, cancellationToken).ConfigureAwait(false),
                _ => await UnknownAsync(command, error).ConfigureAwait(false),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await error.WriteLineAsync($"Error: {ex.Message}").ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> UserAsync(IServiceProvider provider, ParsedArgs args, TextWriter output, TextWriter error, CancellationToken ct)
    {
        var users = provider.GetService<UserService>();
        if (users is null)
        {
            await error.WriteLineAsync("Accounts are kept on the central database; run this command on the API host.").ConfigureAwait(false);
            return 1;
        }

        string sub = args.Positional.Skip(1).FirstOrDefault() ?? "list";
        string? name = args.Positional.Skip(2).FirstOrDefault();
        switch (sub)
        {
            case "create" when name is not null:
                var created = await users.CreateAsync(name, ReadPassword(args, $"Password for {name}: "), args.Option("role") ?? ApiRoles.Admin, ct).ConfigureAwait(false);
                await output.WriteLineAsync($"Created {created.Role} '{created.UserName}'.").ConfigureAwait(false);
                return 0;
            case "list":
                foreach (var u in await users.ListAsync(ct).ConfigureAwait(false))
                {
                    string locked = u.LockoutUntilUtc > DateTime.UtcNow ? "  LOCKED" : "";
                    await output.WriteLineAsync($"{u.UserName,-32} {u.Role,-8} last login {(u.LastLoginUtc?.ToString("u") ?? "never")}{locked}").ConfigureAwait(false);
                }

                return 0;
            case "passwd" when name is not null:
                if (await users.SetPasswordAsync(name, ReadPassword(args, $"New password for {name}: "), ct).ConfigureAwait(false))
                {
                    await output.WriteLineAsync($"Password changed for '{name}'.").ConfigureAwait(false);
                    return 0;
                }

                await error.WriteLineAsync($"No user named '{name}'.").ConfigureAwait(false);
                return 1;
            case "delete" when name is not null:
                if (await users.DeleteAsync(name, ct).ConfigureAwait(false))
                {
                    await output.WriteLineAsync($"Deleted '{name}'.").ConfigureAwait(false);
                    return 0;
                }

                await error.WriteLineAsync($"No user named '{name}'.").ConfigureAwait(false);
                return 1;
            default:
                await error.WriteLineAsync("Usage: banish user create <name> [--role admin|viewer] [--password-stdin] | list | passwd <name> | delete <name>").ConfigureAwait(false);
                return 2;
        }
    }

    /// <summary>
    /// Removes what shells add around a piped password: Windows PowerShell 5.1 starts the stream with a UTF-8
    /// byte order mark (which would silently become part of the password) and ends lines with CR LF.
    /// </summary>
    public static string CleanPasswordLine(string? line) => (line ?? "").TrimStart('﻿').TrimEnd('\r', '\n');

    /// <summary>Reads a password from stdin (<c>--password-stdin</c>, for scripts) or prompts without echo.</summary>
    private static string ReadPassword(ParsedArgs args, string prompt)
    {
        if (args.Flag("password-stdin") || Console.IsInputRedirected)
        {
            return CleanPasswordLine(Console.In.ReadLine());
        }

        Console.Error.Write(prompt);
        var sb = new StringBuilder();
        while (Console.ReadKey(intercept: true) is { Key: not ConsoleKey.Enter } key)
        {
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                sb.Append(key.KeyChar);
            }
        }

        Console.Error.WriteLine();
        return sb.ToString();
    }

    private static async Task<int> ApiKeyAsync(IServiceProvider provider, ParsedArgs args, TextWriter output, TextWriter error, CancellationToken ct)
    {
        var keys = provider.GetService<ApiKeyService>();
        if (keys is null)
        {
            await error.WriteLineAsync("API keys are managed on the central database; this store provider is the Web API itself. Run this command on the API host.").ConfigureAwait(false);
            return 1;
        }

        string sub = args.Positional.Skip(1).FirstOrDefault() ?? "list";
        string? name = args.Positional.Skip(2).FirstOrDefault();
        switch (sub)
        {
            case "create" when name is not null:
                var (entry, key) = await keys.CreateAsync(name, args.Option("role") ?? ApiRoles.Agent, ct).ConfigureAwait(false);
                await output.WriteLineAsync($"Created {entry.Role} key '{entry.Name}'. Copy it now; it cannot be shown again:").ConfigureAwait(false);
                await output.WriteLineAsync(key).ConfigureAwait(false);
                return 0;
            case "list":
                foreach (var k in await keys.ListAsync(ct).ConfigureAwait(false))
                {
                    string state = k.RevokedUtc is null ? "active" : "revoked";
                    await output.WriteLineAsync($"{k.Name,-32} {k.Role,-6} {k.Prefix}...  {state,-8} last used {(k.LastUsedUtc?.ToString("u") ?? "never")}").ConfigureAwait(false);
                }

                return 0;
            case "revoke" when name is not null:
                if (await keys.RevokeAsync(name, ct).ConfigureAwait(false))
                {
                    await output.WriteLineAsync($"Revoked key '{name}'.").ConfigureAwait(false);
                    return 0;
                }

                await error.WriteLineAsync($"No active key named '{name}'.").ConfigureAwait(false);
                return 1;
            default:
                await error.WriteLineAsync("Usage: banish apikey create <name> [--role agent|admin] | list | revoke <name>").ConfigureAwait(false);
                return 2;
        }
    }

    private static async Task<int> ServiceCommandAsync(string command, ParsedArgs args, TextWriter output, TextWriter error, CancellationToken ct)
    {
        var kind = args.Flag("api") ? ServiceKind.Api : ServiceKind.Agent;
        var installer = new ServiceInstaller(new Majorsilence.Banish.Firewall.ProcessRunner());
        if (command == "uninstall")
        {
            var removed = await installer.UninstallAsync(kind, ct).ConfigureAwait(false);
            await (removed.Success ? output : error).WriteLineAsync(removed.Message).ConfigureAwait(false);
            return removed.Success ? 0 : 1;
        }

        string config = Path.GetFullPath(args.Option("config") ?? Environment.GetEnvironmentVariable(BanishConfig.ConfigEnvironmentVariable) ?? BanishConfig.DefaultConfigPath());
        if (!File.Exists(config))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(config)!);
            await File.WriteAllTextAsync(config, SampleConfig.Text + Environment.NewLine, ct).ConfigureAwait(false);
            await output.WriteLineAsync($"Wrote a sample configuration to {config}.").ConfigureAwait(false);
        }

        string exe = ServiceInstaller.ExecutablePath(kind, AppContext.BaseDirectory);
        var result = await installer.InstallAsync(kind, exe, config, !args.Flag("no-start"), ct).ConfigureAwait(false);
        await (result.Success ? output : error).WriteLineAsync(result.Message).ConfigureAwait(false);
        return result.Success ? 0 : 1;
    }

    private static async Task<int> UnknownAsync(string command, TextWriter error)
    {
        await error.WriteLineAsync($"Unknown command '{command}'. Run 'banish help'.").ConfigureAwait(false);
        return 2;
    }

    private static async Task<int> ConfigAsync(ParsedArgs args, BanishOptions options, TextWriter output)
    {
        string sub = args.Positional.Skip(1).FirstOrDefault() ?? "path";
        if (sub == "path")
        {
            await output.WriteLineAsync(args.Option("config")
                ?? Environment.GetEnvironmentVariable(BanishConfig.ConfigEnvironmentVariable)
                ?? BanishConfig.DefaultConfigPath()).ConfigureAwait(false);
            return 0;
        }

        if (sub == "init")
        {
            string target = args.Option("config") ?? Environment.GetEnvironmentVariable(BanishConfig.ConfigEnvironmentVariable) ?? BanishConfig.DefaultConfigPath();
            if (File.Exists(target) && !args.Flag("force"))
            {
                await output.WriteLineAsync($"{target} already exists; use --force to overwrite it.").ConfigureAwait(false);
                return 1;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(target))!);
            await File.WriteAllTextAsync(target, SampleConfig.Text + Environment.NewLine).ConfigureAwait(false);
            await output.WriteLineAsync($"Wrote {target}. Edit it, then run 'banish install'.").ConfigureAwait(false);
            return 0;
        }

        if (sub == "show")
        {
            var redacted = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
            var copy = System.Text.Json.JsonSerializer.Deserialize<BanishOptions>(System.Text.Json.JsonSerializer.Serialize(options))!;
            copy.Store.ConnectionString = copy.Store.ConnectionString is null ? null : "***";
            copy.Store.ApiKey = copy.Store.ApiKey is null ? null : "***";
            await output.WriteLineAsync(System.Text.Json.JsonSerializer.Serialize(copy, redacted)).ConfigureAwait(false);
            return 0;
        }

        await output.WriteLineAsync("Usage: banish config path|show|init").ConfigureAwait(false);
        return 2;
    }

    private static async Task<int> TestRuleAsync(ParsedArgs args, BanishOptions options, TextWriter output, TextWriter error)
    {
        string? ruleName = args.Positional.Skip(1).FirstOrDefault();
        string? file = args.Positional.Skip(2).FirstOrDefault();
        if (ruleName is null || file is null)
        {
            await error.WriteLineAsync("Usage: banish test-rule <rule> <logfile>").ConfigureAwait(false);
            return 2;
        }

        var rule = options.Rules?.FirstOrDefault(r => r.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase));
        if (rule is null)
        {
            string known = string.Join(", ", (options.Rules ?? []).Select(r => r.Name));
            await error.WriteLineAsync($"No rule named '{ruleName}'. Known rules: {known}").ConfigureAwait(false);
            return 1;
        }

        var matcher = new RuleMatcher(rule);
        var hits = new Dictionary<string, int>();
        int lines = 0;
        int matched = 0;
        foreach (string line in File.ReadLines(file))
        {
            lines++;
            if (matcher.TryMatch(line, out var address))
            {
                matched++;
                hits[address.ToString()] = hits.GetValueOrDefault(address.ToString()) + 1;
            }
        }

        await output.WriteLineAsync($"{lines} lines, {matched} matched, {hits.Count} addresses (rule {rule.Name}: ban at {rule.MaxRetry} failures in {rule.FindTimeSeconds}s)").ConfigureAwait(false);
        foreach (var (ip, count) in hits.OrderByDescending(h => h.Value).ThenBy(h => h.Key))
        {
            await output.WriteLineAsync($"  {ip,-40} {count,6}{(count >= rule.MaxRetry ? "  would reach threshold" : "")}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> StatusAsync(IBanStore store, BanishOptions options, TextWriter output, CancellationToken ct)
    {
        var stats = await store.GetStatsAsync(ct).ConfigureAwait(false);
        await output.WriteLineAsync($"Store:        {options.Store.Provider}").ConfigureAwait(false);
        await output.WriteLineAsync($"Active bans:  {stats.ActiveBans} ({stats.PermanentBans} permanent)").ConfigureAwait(false);
        await output.WriteLineAsync($"Last 24h:     {stats.BansLast24Hours} new bans").ConfigureAwait(false);
        await output.WriteLineAsync($"All time:     {stats.TotalBans}").ConfigureAwait(false);
        foreach (var rule in stats.TopRules)
        {
            await output.WriteLineAsync($"  rule {rule.Key,-20} {rule.Count}").ConfigureAwait(false);
        }

        await output.WriteLineAsync($"Agents:       {stats.Agents.Count}").ConfigureAwait(false);
        foreach (var agent in stats.Agents)
        {
            await output.WriteLineAsync($"  {agent.MachineName,-24} {agent.Firewall,-16} {agent.AppliedBans,6} applied   seen {agent.LastSeenUtc:u}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> ListAsync(IBanStore store, ParsedArgs args, TextWriter output, CancellationToken ct)
    {
        string state = args.Flag("all") ? "all" : args.Flag("removed") ? "removed" : args.Flag("expired") ? "expired" : "active";
        int take = int.TryParse(args.Option("take"), out int t) ? t : 100;
        var result = await store.QueryAsync(new BanQuery { State = state, Search = args.Option("search"), Take = take }, ct).ConfigureAwait(false);
        var sb = new StringBuilder();
        sb.AppendLine($"{"ADDRESS",-40} {"EXPIRES (UTC)",-20} {"SOURCE",-18} {"RULE",-14} REASON");
        foreach (var ban in result.Items)
        {
            string expires = ban.RemovedUtc is not null ? "removed" : ban.ExpiresUtc is null ? "permanent" : ban.ExpiresUtc.Value.ToString("yyyy-MM-dd HH:mm:ss");
            sb.AppendLine($"{ban.Address,-40} {expires,-20} {ban.Source,-18} {ban.RuleId,-14} {ban.Reason}");
        }

        sb.AppendLine($"{result.Items.Count} of {result.Total} shown");
        await output.WriteAsync(sb.ToString()).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> BanAsync(IBanStore store, BanishOptions options, ParsedArgs args, TextWriter output, TextWriter error, CancellationToken ct)
    {
        string? target = args.Positional.Skip(1).FirstOrDefault();
        if (target is null || !IpAddressUtil.TryParseNetwork(target, out var network))
        {
            await error.WriteLineAsync("Usage: banish ban <ip|cidr> [--reason <text>] [--for <duration>] [--force]").ConfigureAwait(false);
            return 2;
        }

        if (!IpAddressUtil.IsBannable(network))
        {
            await error.WriteLineAsync($"{target} cannot be banned (reserved address or range wider than /{IpAddressUtil.MinIPv4Prefix} IPv4 or /{IpAddressUtil.MinIPv6Prefix} IPv6).").ConfigureAwait(false);
            return 1;
        }

        var allow = Allowlist.Create(options.Allowlist.Entries, options.Allowlist.IncludePrivateRanges)
            .With((await store.GetAllowlistAsync(ct).ConfigureAwait(false)).Select(a => a.Address));
        if (allow.Overlaps(network) && !args.Flag("force"))
        {
            await error.WriteLineAsync($"{target} is, or contains, an allow-listed or local address. Use --force to ban anyway.").ConfigureAwait(false);
            return 1;
        }

        TimeSpan? duration = null;
        if (args.Option("for") is { } text && !Duration.TryParse(text, out duration))
        {
            await error.WriteLineAsync($"Invalid duration '{text}'. Use e.g. 30m, 2h, 7d or permanent.").ConfigureAwait(false);
            return 2;
        }

        var now = DateTime.UtcNow;
        var ban = await store.AddAsync(new Ban
        {
            Address = IpAddressUtil.Format(network),
            Reason = args.Option("reason") ?? "manual ban",
            Source = BanSources.Manual,
            CreatedUtc = now,
            ExpiresUtc = duration is null ? null : now + duration,
            MachineName = options.MachineName,
            CreatedBy = Environment.UserName,
            Hits = 0,
        }, ct).ConfigureAwait(false);
        await output.WriteLineAsync($"Banned {ban.Address} ({(ban.ExpiresUtc is null ? "permanent" : "until " + ban.ExpiresUtc.Value.ToString("u"))}). Agents apply it within their reconcile interval.").ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> UnbanAsync(IBanStore store, ParsedArgs args, TextWriter output, TextWriter error, CancellationToken ct)
    {
        string? target = args.Positional.Skip(1).FirstOrDefault();
        if (target is null || !IpAddressUtil.TryNormalize(target, out string normalized))
        {
            await error.WriteLineAsync("Usage: banish unban <ip|cidr>").ConfigureAwait(false);
            return 2;
        }

        int count = await store.RemoveAsync(normalized, Environment.UserName, ct).ConfigureAwait(false);
        if (count == 0)
        {
            await error.WriteLineAsync($"{normalized} has no active ban.").ConfigureAwait(false);
            return 1;
        }

        await output.WriteLineAsync($"Unbanned {normalized}.").ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> AllowAsync(IBanStore store, ParsedArgs args, TextWriter output, TextWriter error, CancellationToken ct)
    {
        string sub = args.Positional.Skip(1).FirstOrDefault() ?? "list";
        string? target = args.Positional.Skip(2).FirstOrDefault();
        switch (sub)
        {
            case "list":
                foreach (var entry in await store.GetAllowlistAsync(ct).ConfigureAwait(false))
                {
                    await output.WriteLineAsync($"{entry.Address,-40} {entry.Note}").ConfigureAwait(false);
                }

                return 0;
            case "add" when target is not null && IpAddressUtil.TryNormalize(target, out string normalized):
                await store.AddAllowAsync(new AllowEntry { Address = normalized, Note = args.Option("note"), CreatedBy = Environment.UserName }, ct).ConfigureAwait(false);
                await output.WriteLineAsync($"Allow-listed {normalized}.").ConfigureAwait(false);
                return 0;
            case "remove" when target is not null && IpAddressUtil.TryNormalize(target, out string toRemove):
                if (await store.RemoveAllowAsync(toRemove, ct).ConfigureAwait(false))
                {
                    await output.WriteLineAsync($"Removed {toRemove} from the allow-list.").ConfigureAwait(false);
                    return 0;
                }

                await error.WriteLineAsync($"{toRemove} is not on the allow-list.").ConfigureAwait(false);
                return 1;
            default:
                await error.WriteLineAsync("Usage: banish allow list | add <ip|cidr> [--note <text>] | remove <ip|cidr>").ConfigureAwait(false);
                return 2;
        }
    }
}

/// <summary>Minimal argument parser: positional arguments, <c>--name value</c> options and <c>--flag</c>s.</summary>
public sealed class ParsedArgs
{
    private static readonly HashSet<string> Flags = ["all", "removed", "expired", "force", "dry-run", "password-stdin", "api", "no-start"];
    private readonly Dictionary<string, string> _options = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Positional { get; } = [];

    public string? Option(string name) => _options.GetValueOrDefault(name);

    public bool Flag(string name) => _flags.Contains(name);

    public static ParsedArgs Parse(string[] args)
    {
        var parsed = new ParsedArgs();
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.StartsWith("--", StringComparison.Ordinal) && arg.Length > 2)
            {
                string name = arg[2..];
                if (Flags.Contains(name) || i + 1 >= args.Length)
                {
                    parsed._flags.Add(name);
                }
                else
                {
                    parsed._options[name] = args[++i];
                }
            }
            else
            {
                parsed.Positional.Add(arg);
            }
        }

        return parsed;
    }
}
