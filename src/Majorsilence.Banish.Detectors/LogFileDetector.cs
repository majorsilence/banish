using Majorsilence.Banish.Core;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Detectors;

/// <summary>Tails one or more log files (wildcards allowed in the file name) and matches lines against a rule.</summary>
public sealed class LogFileDetector : IDetector
{
    private readonly RuleMatcher _matcher;
    private readonly ILogger _logger;
    private readonly TimeSpan _poll;
    private readonly TimeProvider _time;

    public LogFileDetector(RuleOptions rule, ILogger logger, TimeSpan? pollInterval = null, TimeProvider? time = null)
    {
        _matcher = new RuleMatcher(rule);
        _logger = logger;
        _poll = pollInterval ?? TimeSpan.FromMilliseconds(500);
        _time = time ?? TimeProvider.System;
    }

    public string Name => _matcher.Rule.Name;

    public async Task RunAsync(Func<FailureEvent, ValueTask> onFailure, CancellationToken cancellationToken)
    {
        var files = new Dictionary<string, TailedFile>(StringComparer.Ordinal);
        var nextScan = DateTime.MinValue;
        bool firstScan = true;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var now = DateTime.UtcNow;
                if (now >= nextScan)
                {
                    Rescan(files, firstScan);
                    firstScan = false;
                    nextScan = now.AddSeconds(5);
                }

                foreach (var tail in files.Values)
                {
                    foreach (string line in tail.ReadNewLines())
                    {
                        if (_matcher.TryMatch(line, out var address))
                        {
                            await onFailure(new FailureEvent(address, Name, _time.GetUtcNow().UtcDateTime, line)).ConfigureAwait(false);
                        }
                    }
                }

                await Task.Delay(_poll, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            foreach (var tail in files.Values)
            {
                tail.Dispose();
            }
        }
    }

    private void Rescan(Dictionary<string, TailedFile> files, bool firstScan)
    {
        foreach (string pattern in _matcher.Rule.Paths)
        {
            foreach (string path in ExpandPaths(pattern))
            {
                if (!files.ContainsKey(path))
                {
                    // Files that appear after startup are read from their start; those present at startup honour ReadFromStart.
                    files[path] = new TailedFile(path, !firstScan || _matcher.Rule.ReadFromStart);
                    _logger.LogInformation("Rule {Rule}: watching {Path}", Name, path);
                }
            }
        }
    }

    internal static IEnumerable<string> ExpandPaths(string pattern)
    {
        string? directory = Path.GetDirectoryName(pattern);
        string filePattern = Path.GetFileName(pattern);
        if (string.IsNullOrEmpty(filePattern))
        {
            return [];
        }

        if (filePattern.IndexOfAny(['*', '?']) < 0)
        {
            return [pattern];
        }

        try
        {
            return Directory.Exists(directory) ? Directory.GetFiles(directory, filePattern) : [];
        }
        catch (IOException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
    }
}
