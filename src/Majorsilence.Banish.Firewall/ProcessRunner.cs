using System.Diagnostics;

namespace Majorsilence.Banish.Firewall;

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Success => ExitCode == 0;
}

/// <summary>Runs external programs; abstracted so firewall providers can be tested without root.</summary>
public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, string? stdin, CancellationToken cancellationToken);
}

public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, string? stdin, CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo(fileName)
        {
            RedirectStandardInput = stdin is not null,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string arg in arguments)
        {
            info.ArgumentList.Add(arg);
        }

        try
        {
            using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start " + fileName);
            var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
            if (stdin is not null)
            {
                await process.StandardInput.WriteAsync(stdin.AsMemory(), cancellationToken).ConfigureAwait(false);
                process.StandardInput.Close();
            }

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return new ProcessResult(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return new ProcessResult(127, "", $"{fileName}: {ex.Message}");
        }
    }
}

public sealed class FirewallException(string message) : Exception(message);

internal static class ProcessResultExtensions
{
    public static void ThrowIfFailed(this ProcessResult result, string what)
    {
        if (!result.Success)
        {
            throw new FirewallException($"{what} failed (exit {result.ExitCode}): {result.StdErr.Trim()}");
        }
    }
}
