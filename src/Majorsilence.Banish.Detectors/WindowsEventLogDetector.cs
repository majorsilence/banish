using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Majorsilence.Banish.Core;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Detectors;

/// <summary>
/// Subscribes to a Windows Event Log. Each event's XML is matched against the rule's patterns, e.g.
/// <c>&lt;Data Name='IpAddress'&gt;(?&lt;ip&gt;[^&lt;]+)&lt;/Data&gt;</c> for failed logons (event 4625).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogDetector : IDetector
{
    private readonly RuleMatcher _matcher;
    private readonly ILogger _logger;

    public WindowsEventLogDetector(RuleOptions rule, ILogger logger)
    {
        _matcher = new RuleMatcher(rule);
        _logger = logger;
    }

    public string Name => _matcher.Rule.Name;

    public async Task RunAsync(Func<FailureEvent, ValueTask> onFailure, CancellationToken cancellationToken)
    {
        var rule = _matcher.Rule;
        var query = new EventLogQuery(rule.EventLog ?? "Security", PathType.LogName, rule.EventQuery ?? "*");
        var channel = System.Threading.Channels.Channel.CreateUnbounded<string>();
        using var watcher = new EventLogWatcher(query, bookmark: null, readExistingEvents: false);
        bool receivedAny = false;
        watcher.EventRecordWritten += (_, args) =>
        {
            if (args.EventRecord is null)
            {
                // On .NET a failed subscription is reported here instead of being thrown, so it must not be ignored.
                // Reading the Security log without permission shows up as EventLogException "The handle is invalid."
                // before any event has arrived; later errors are per-record and only worth a warning.
                if (args.EventException is { } problem)
                {
                    if (problem is UnauthorizedAccessException or EventLogNotFoundException or EventLogInvalidDataException
                        || (!receivedAny && problem is EventLogException))
                    {
                        channel.Writer.TryComplete(problem);
                    }
                    else
                    {
                        _logger.LogWarning(problem, "Rule {Rule}: event log subscription reported a problem", Name);
                    }
                }

                return;
            }

            receivedAny = true;
            using (args.EventRecord)
            {
                channel.Writer.TryWrite(args.EventRecord.ToXml());
            }
        };
        watcher.Enabled = true;
        _logger.LogInformation("Rule {Rule}: subscribed to {Log}", Name, rule.EventLog ?? "Security");

        try
        {
            await foreach (string xml in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                if (_matcher.TryMatch(xml, out var address))
                {
                    await onFailure(new FailureEvent(address, Name, DateTime.UtcNow, null)).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            throw new InvalidOperationException(
                $"Rule {Name}: cannot read the {rule.EventLog ?? "Security"} event log ({ex.Message}). Run the agent as an administrator " +
                "(the service runs as LocalSystem by default), or add its account to the 'Event Log Readers' group.", ex);
        }
    }
}
