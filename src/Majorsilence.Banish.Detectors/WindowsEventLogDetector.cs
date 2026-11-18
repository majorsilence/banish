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
        watcher.EventRecordWritten += (_, args) =>
        {
            if (args.EventRecord is null)
            {
                return;
            }

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
    }
}
