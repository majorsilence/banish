using Majorsilence.Banish.Core;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Detectors;

public static class DetectorFactory
{
    public static IDetector? Create(RuleOptions rule, ILogger logger)
    {
        switch (rule.Detector.ToLowerInvariant())
        {
            case "logfile":
                return new LogFileDetector(rule, logger);
            case "command":
                return new CommandDetector(rule, logger);
            case "windowseventlog":
                if (OperatingSystem.IsWindows())
                {
                    return new WindowsEventLogDetector(rule, logger);
                }

                logger.LogWarning("Rule {Rule}: WindowsEventLog detector is only available on Windows; skipped", rule.Name);
                return null;
            default:
                logger.LogError("Rule {Rule}: unknown detector '{Detector}'", rule.Name, rule.Detector);
                return null;
        }
    }
}
