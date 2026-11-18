using Majorsilence.Banish.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

string? configPath = null;
for (int i = 0; i < args.Length - 1; i++)
{
    if (args[i] == "--config")
    {
        configPath = args[i + 1];
    }
}

var options = BanishConfig.Load(configPath);
var builder = Host.CreateApplicationBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
builder.Logging.AddSimpleConsole(o => o.TimestampFormat = "yyyy-MM-dd HH:mm:ss ");
builder.Services.AddWindowsService(o => o.ServiceName = "Banish");
builder.Services.AddSystemd();
builder.Services.AddBanishAgent(options);
await builder.Build().RunAsync();
