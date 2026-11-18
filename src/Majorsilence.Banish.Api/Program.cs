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
if (args.Contains("--healthcheck"))
{
    // Used by the container HEALTHCHECK: ask the running instance on its first listen URL.
    string url = options.Api.Urls.Split(';')[0].Replace("0.0.0.0", "127.0.0.1").Replace("+", "127.0.0.1").Replace("*", "127.0.0.1");
    try
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
        return (await http.GetAsync(url.TrimEnd('/') + "/api/v1/health")).IsSuccessStatusCode ? 0 : 1;
    }
    catch (HttpRequestException)
    {
        return 1;
    }
    catch (TaskCanceledException)
    {
        return 1;
    }
}

await ApiHost.Build(options, args).RunAsync();
return 0;
