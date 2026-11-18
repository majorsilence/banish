using Majorsilence.Banish.Core;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Firewall;

public static class FirewallFactory
{
    public static IFirewall Create(string provider, IProcessRunner runner, ILogger logger)
    {
        switch (provider.ToLowerInvariant())
        {
            case "dryrun":
                return new DryRunFirewall(logger);
            case "none":
                return new NullFirewall();
            case "nftables":
                return new NftablesFirewall(runner);
            case "iptables":
                return new IptablesFirewall(runner);
            case "pf":
                return new PfFirewall(runner);
            case "windows":
                return OperatingSystem.IsWindows()
                    ? new WindowsFirewall()
                    : throw new PlatformNotSupportedException("The Windows firewall provider only runs on Windows.");
            case "auto":
                return Detect(runner, logger);
            default:
                throw new ArgumentException($"Unknown firewall provider '{provider}'.");
        }
    }

    private static IFirewall Detect(IProcessRunner runner, ILogger logger)
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsFirewall();
        }

        if (OperatingSystem.IsMacOS())
        {
            return new PfFirewall(runner);
        }

        if (OnPath("nft"))
        {
            return new NftablesFirewall(runner);
        }

        if (OnPath("ipset") && OnPath("iptables"))
        {
            return new IptablesFirewall(runner);
        }

        logger.LogWarning("No supported firewall tool found (nft, or ipset+iptables); running in dry-run mode.");
        return new DryRunFirewall(logger);
    }

    private static bool OnPath(string program)
    {
        string[] dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator);
        string[] extra = ["/usr/sbin", "/sbin", "/usr/local/sbin"];
        return dirs.Concat(extra).Any(d => d.Length > 0 && File.Exists(Path.Combine(d, program)));
    }
}
