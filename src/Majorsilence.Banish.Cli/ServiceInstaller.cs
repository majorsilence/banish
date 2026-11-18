using System.Text;
using Majorsilence.Banish.Firewall;

namespace Majorsilence.Banish.Cli;

public enum ServiceKind
{
    /// <summary>Watches logs and edits the firewall; needs administrator rights.</summary>
    Agent,

    /// <summary>The central Web API and dashboard; needs none.</summary>
    Api,
}

/// <summary>Where the operating system keeps service definitions; injectable so tests do not touch the real system.</summary>
public sealed record ServicePaths(string SystemdDirectory, string LaunchdDirectory)
{
    public static ServicePaths Default => new("/etc/systemd/system", "/Library/LaunchDaemons");
}

/// <summary>Registers Banish as a Windows service, a systemd unit or a launchd daemon.</summary>
public sealed class ServiceInstaller
{
    private readonly IProcessRunner _runner;
    private readonly ServicePaths _paths;

    public ServiceInstaller(IProcessRunner runner, ServicePaths? paths = null)
    {
        _runner = runner;
        _paths = paths ?? ServicePaths.Default;
    }

    public static string ServiceName(ServiceKind kind) => kind == ServiceKind.Agent ? "Banish" : "BanishApi";

    public static string UnitName(ServiceKind kind) => kind == ServiceKind.Agent ? "banish-agent" : "banish-api";

    public static string LaunchdLabel(ServiceKind kind) => "com.majorsilence." + UnitName(kind);

    /// <summary>The executable that sits next to the <c>banish</c> command.</summary>
    public static string ExecutablePath(ServiceKind kind, string directory) =>
        Path.Combine(directory, UnitName(kind) + (OperatingSystem.IsWindows() ? ".exe" : ""));

    public static string BuildSystemdUnit(ServiceKind kind, string exePath, string configPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("[Unit]");
        sb.AppendLine(kind == ServiceKind.Agent
            ? "Description=Banish intrusion prevention agent"
            : "Description=Banish central ban registry and dashboard");
        sb.AppendLine("Documentation=https://github.com/majorsilence/banish");
        sb.AppendLine("After=network-online.target");
        sb.AppendLine("Wants=network-online.target");
        sb.AppendLine();
        sb.AppendLine("[Service]");
        sb.AppendLine("Type=notify");
        sb.AppendLine($"ExecStart={Quote(exePath)} --config {Quote(configPath)}");
        sb.AppendLine("Restart=on-failure");
        sb.AppendLine("RestartSec=5");
        sb.AppendLine("NoNewPrivileges=true");
        sb.AppendLine("PrivateTmp=true");
        sb.AppendLine("ProtectHome=true");
        if (kind == ServiceKind.Api)
        {
            // The API needs no privileges: run it as a throw-away user with its own state directory.
            sb.AppendLine("DynamicUser=yes");
            sb.AppendLine("StateDirectory=banish");
            sb.AppendLine("ConfigurationDirectory=banish");
            sb.AppendLine("ProtectSystem=strict");
            sb.AppendLine("ProtectKernelTunables=true");
            sb.AppendLine("ProtectControlGroups=true");
            sb.AppendLine("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX");
            sb.AppendLine("CapabilityBoundingSet=");
        }
        else
        {
            // The agent edits the firewall (CAP_NET_ADMIN) and reads logs, so it stays root with a trimmed system view.
            sb.AppendLine("ProtectSystem=full");
            sb.AppendLine("ReadWritePaths=/var/lib/banish");
            sb.AppendLine("StateDirectory=banish");
        }

        sb.AppendLine();
        sb.AppendLine("[Install]");
        sb.AppendLine("WantedBy=multi-user.target");
        return sb.ToString();
    }

    public static string BuildLaunchdPlist(ServiceKind kind, string exePath, string configPath)
    {
        string E(string s) => System.Security.SecurityElement.Escape(s) ?? "";
        string log = $"/var/log/{UnitName(kind)}.log";
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>Label</key><string>{E(LaunchdLabel(kind))}</string>
              <key>ProgramArguments</key>
              <array>
                <string>{E(exePath)}</string>
                <string>--config</string>
                <string>{E(configPath)}</string>
              </array>
              <key>RunAtLoad</key><true/>
              <key>KeepAlive</key><true/>
              <key>StandardOutPath</key><string>{E(log)}</string>
              <key>StandardErrorPath</key><string>{E(log)}</string>
            </dict>
            </plist>
            """;
    }

    /// <summary>Arguments for <c>sc.exe create</c>.</summary>
    public static string[] BuildWindowsCreateArguments(ServiceKind kind, string exePath, string configPath) =>
    [
        "create", ServiceName(kind),
        "binPath=", $"\"{exePath}\" --config \"{configPath}\"",
        "start=", "auto",
        "DisplayName=", kind == ServiceKind.Agent ? "Banish agent" : "Banish API and dashboard",
    ];

    public async Task<(bool Success, string Message)> InstallAsync(ServiceKind kind, string exePath, string configPath, bool start, CancellationToken ct)
    {
        if (!File.Exists(exePath))
        {
            return (false, $"Cannot find {exePath}. Run banish from the folder that contains {Path.GetFileName(exePath)}.");
        }

        if (OperatingSystem.IsWindows())
        {
            var create = await _runner.RunAsync("sc.exe", BuildWindowsCreateArguments(kind, exePath, configPath), null, ct).ConfigureAwait(false);
            if (!create.Success)
            {
                return (false, $"sc.exe create failed: {Describe(create)} (run from an elevated prompt)");
            }

            await _runner.RunAsync("sc.exe", ["description", ServiceName(kind), "Blocks abusive IP addresses and shares bans between machines."], null, ct).ConfigureAwait(false);
            await _runner.RunAsync("sc.exe", ["failure", ServiceName(kind), "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"], null, ct).ConfigureAwait(false);
            if (start)
            {
                var started = await _runner.RunAsync("sc.exe", ["start", ServiceName(kind)], null, ct).ConfigureAwait(false);
                if (!started.Success)
                {
                    return (false, $"The service was created but did not start: {Describe(started)}");
                }
            }

            return (true, $"Installed the {ServiceName(kind)} service.");
        }

        if (OperatingSystem.IsMacOS())
        {
            string plist = Path.Combine(_paths.LaunchdDirectory, LaunchdLabel(kind) + ".plist");
            await File.WriteAllTextAsync(plist, BuildLaunchdPlist(kind, exePath, configPath), ct).ConfigureAwait(false);
            if (start)
            {
                var load = await _runner.RunAsync("launchctl", ["load", "-w", plist], null, ct).ConfigureAwait(false);
                if (!load.Success)
                {
                    return (false, $"launchctl load failed: {Describe(load)}");
                }
            }

            return (true, $"Installed {plist}.");
        }

        string unit = Path.Combine(_paths.SystemdDirectory, UnitName(kind) + ".service");
        await File.WriteAllTextAsync(unit, BuildSystemdUnit(kind, exePath, configPath), ct).ConfigureAwait(false);
        var reload = await _runner.RunAsync("systemctl", ["daemon-reload"], null, ct).ConfigureAwait(false);
        if (!reload.Success)
        {
            return (false, $"Wrote {unit}, but systemctl failed: {Describe(reload)}");
        }

        var enable = await _runner.RunAsync("systemctl", start ? ["enable", "--now", UnitName(kind)] : ["enable", UnitName(kind)], null, ct).ConfigureAwait(false);
        return enable.Success
            ? (true, $"Installed and enabled {UnitName(kind)}.service.")
            : (false, $"Wrote {unit}, but enabling it failed: {Describe(enable)}");
    }

    public async Task<(bool Success, string Message)> UninstallAsync(ServiceKind kind, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
        {
            await _runner.RunAsync("sc.exe", ["stop", ServiceName(kind)], null, ct).ConfigureAwait(false);
            var delete = await _runner.RunAsync("sc.exe", ["delete", ServiceName(kind)], null, ct).ConfigureAwait(false);
            return delete.Success ? (true, $"Removed the {ServiceName(kind)} service.") : (false, $"sc.exe delete failed: {Describe(delete)}");
        }

        if (OperatingSystem.IsMacOS())
        {
            string plist = Path.Combine(_paths.LaunchdDirectory, LaunchdLabel(kind) + ".plist");
            await _runner.RunAsync("launchctl", ["unload", "-w", plist], null, ct).ConfigureAwait(false);
            if (File.Exists(plist))
            {
                File.Delete(plist);
            }

            return (true, $"Removed {plist}.");
        }

        string unit = Path.Combine(_paths.SystemdDirectory, UnitName(kind) + ".service");
        await _runner.RunAsync("systemctl", ["disable", "--now", UnitName(kind)], null, ct).ConfigureAwait(false);
        if (File.Exists(unit))
        {
            File.Delete(unit);
        }

        await _runner.RunAsync("systemctl", ["daemon-reload"], null, ct).ConfigureAwait(false);
        return (true, $"Removed {UnitName(kind)}.service.");
    }

    private static string Quote(string path) => path.Contains(' ') ? $"\"{path}\"" : path;

    private static string Describe(ProcessResult r) => string.IsNullOrWhiteSpace(r.StdErr) ? (r.StdOut.Trim() is { Length: > 0 } o ? o : $"exit {r.ExitCode}") : r.StdErr.Trim();
}
