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
        var configuration = builder.Build();
        var options = new BanishOptions();
        configuration.Bind(options);
        options.Rules ??= DefaultRules.ForCurrentOs();
        options.Api.Urls = NormalizeUrls(configuration.GetSection("Api:Urls"), options.Api.Urls);
        return options;
    }

    /// <summary>
    /// <c>Api:Urls</c> is one string with addresses separated by semicolons. A JSON array is accepted too
    /// (the configuration binder would otherwise ignore it and the API would quietly listen on the default
    /// port). Every address must be an absolute http or https URL; anything else stops start-up with a message.
    /// </summary>
    public static string NormalizeUrls(IConfigurationSection section, string current)
    {
        string[] children = section.GetChildren().Select(c => c.Value).Where(v => !string.IsNullOrWhiteSpace(v)).ToArray()!;
        string joined = children.Length > 0 ? string.Join(';', children)
            : !string.IsNullOrWhiteSpace(section.Value) ? section.Value : current;
        var urls = joined.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (urls.Length == 0)
        {
            throw new InvalidOperationException("Api:Urls is empty. Use for example \"http://127.0.0.1:5380\" (several addresses separated by ';').");
        }

        foreach (string url in urls)
        {
            // Kestrel also accepts wildcard hosts such as http://+:5380 and http://*:5380, which Uri rejects.
            string probe = url.Replace("://+", "://localhost").Replace("://*", "://localhost");
            if (!Uri.TryCreate(probe, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new InvalidOperationException($"Api:Urls contains '{url}', which is not an absolute http or https URL.");
            }
        }

        return string.Join(';', urls);
    }
}
