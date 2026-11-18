using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Cli;

internal static class SyncCommand
{
    public static async Task<int> RunAsync(IBanStore store, BanishOptions options, bool dryRun, TextWriter output, TextWriter error, CancellationToken ct)
    {
        await error.WriteLineAsync("Blocklist sync is not implemented yet.").ConfigureAwait(false);
        return 1;
    }
}
