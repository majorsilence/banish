using System.Diagnostics;
using Majorsilence.Banish.Core;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Detectors;

/// <summary>Runs a long-lived command (journalctl -f, log stream...) and matches each output line.</summary>
public sealed class CommandDetector : IDetector
{
    private readonly RuleMatcher _matcher;
    private readonly ILogger _logger;

    public CommandDetector(RuleOptions rule, ILogger logger)
    {
        _matcher = new RuleMatcher(rule);
        _logger = logger;
    }

    public string Name => _matcher.Rule.Name;

    public async Task RunAsync(Func<FailureEvent, ValueTask> onFailure, CancellationToken cancellationToken)
    {
        var command = _matcher.Rule.Command;
        if (command.Count == 0)
        {
            _logger.LogError("Rule {Rule}: Command detector needs a Command", Name);
            return;
        }

        var delay = TimeSpan.FromSeconds(2);
        while (!cancellationToken.IsCancellationRequested)
        {
            var started = DateTime.UtcNow;
            try
            {
                await RunOnceAsync(command, onFailure, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
            {
                _logger.LogError(ex, "Rule {Rule}: command {Command} failed", Name, command[0]);
            }

            // Restart with backoff; a command that ran for a while resets the delay.
            delay = DateTime.UtcNow - started > TimeSpan.FromMinutes(1) ? TimeSpan.FromSeconds(2) : TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, TimeSpan.FromMinutes(1).Ticks));
            try
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task RunOnceAsync(List<string> command, Func<FailureEvent, ValueTask> onFailure, CancellationToken ct)
    {
        var info = new ProcessStartInfo(command[0])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string arg in command.Skip(1))
        {
            info.ArgumentList.Add(arg);
        }

        using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start " + command[0]);
        using var registration = ct.Register(() =>
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }
        });

        _logger.LogInformation("Rule {Rule}: reading output of {Command}", Name, command[0]);
        _ = process.StandardError.ReadToEndAsync(CancellationToken.None);
        string? line;
        while ((line = await process.StandardOutput.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            if (_matcher.TryMatch(line, out var address))
            {
                await onFailure(new FailureEvent(address, Name, DateTime.UtcNow, line)).ConfigureAwait(false);
            }
        }

        await process.WaitForExitAsync(ct).ConfigureAwait(false);
    }
}
