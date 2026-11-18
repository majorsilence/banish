using Majorsilence.Banish.Api;
using Majorsilence.Banish.Hosting;

string? configPath = null;
for (int i = 0; i < args.Length - 1; i++)
{
    if (args[i] == "--config")
    {
        configPath = args[i + 1];
    }
}

var options = BanishConfig.Load(configPath);
await ApiHost.Build(options, args).RunAsync();
