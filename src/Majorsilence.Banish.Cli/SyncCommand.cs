using Majorsilence.Banish.Core;
using Majorsilence.Banish.Hosting;
using Majorsilence.Banish.Sync;
using Microsoft.Extensions.DependencyInjection;

namespace Majorsilence.Banish.Cli;

internal static class SyncCommand
{
    /// <summary>Refreshes every enabled blocklist once and prints what changed.</summary>
    public static async Task<int> RunAsync(BanishOptions options, bool dryRun, TextWriter output, TextWriter error, CancellationToken ct)
    {
        if (!options.Sync.Sources.Any(s => s.Enabled))
        {
            await error.WriteLineAsync("No blocklist sources are enabled. Add them under Sync:Sources in the configuration.").ConfigureAwait(false);
            return 1;
        }

        await using var provider = new ServiceCollection()
            .AddLogging()
            .AddBanishStore(options)
            .AddSingleton(new AllowlistProvider(options.Allowlist))
            .AddBanishSync(options, runInBackground: false)
            .BuildServiceProvider();
        var sync = provider.GetRequiredService<IBlocklistSync>();
        var results = await sync.RunAllAsync(dryRun, ct).ConfigureAwait(false);

        await output.WriteLineAsync($"{"SOURCE",-24} {"STATUS",-13} {"FETCHED",8} {"VALID",8} {"SKIPPED",8} {"ADDED",8} {"REMOVED",8}").ConfigureAwait(false);
        foreach (var r in results)
        {
            await output.WriteLineAsync($"{r.Source,-24} {r.Status,-13} {r.Fetched,8} {r.Valid,8} {r.Skipped,8} {r.Added,8} {r.Removed,8}").ConfigureAwait(false);
            if (r.Message is not null)
            {
                await output.WriteLineAsync($"  {r.Message}").ConfigureAwait(false);
            }
        }

        if (dryRun)
        {
            await output.WriteLineAsync("Dry run: nothing was changed.").ConfigureAwait(false);
        }

        return results.Any(r => r.Status is SyncStatus.Error or SyncStatus.Refused) ? 1 : 0;
    }
}
