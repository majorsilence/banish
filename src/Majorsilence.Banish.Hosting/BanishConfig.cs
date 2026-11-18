using Majorsilence.Banish.Core;
using Majorsilence.Banish.Detectors;
using Majorsilence.Banish.Store.Ef;
using Microsoft.Extensions.Configuration;

namespace Majorsilence.Banish.Hosting;

public static class BanishConfig
{
    public const string ConfigEnvironmentVariable = "BANISH_CONFIG";

    public static string DefaultConfigPath()
    {
        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(EfStoreRegistration.DefaultDataDirectory(), "banish.json");
        }

        return OperatingSystem.IsMacOS()
            ? "/Library/Application Support/Banish/banish.json"
            : "/etc/banish/banish.json";
    }

    /// <summary>
    /// Loads configuration: defaults, then the JSON file (explicit path, <c>BANISH_CONFIG</c>, or the
    /// OS default), then <c>BANISH__Section__Key</c> environment variables.
    /// </summary>
    public static BanishOptions Load(string? path = null)
    {
        path ??= Environment.GetEnvironmentVariable(ConfigEnvironmentVariable) ?? DefaultConfigPath();
        var builder = new ConfigurationBuilder();
        builder.AddJsonFile(Path.GetFullPath(path), optional: true, reloadOnChange: false);
        builder.AddEnvironmentVariables("BANISH__");
        var options = new BanishOptions();
        builder.Build().Bind(options);
        options.Rules ??= DefaultRules.ForCurrentOs();
        return options;
    }
}
