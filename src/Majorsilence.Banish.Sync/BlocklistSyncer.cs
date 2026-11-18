using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Majorsilence.Banish.Core;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Sync;

/// <summary>
/// Refreshes blocklists. For each source it downloads the list, validates every entry, drops
/// allow-listed ones, then adds new entries and lifts ones that left the list. A download that
/// looks wrong (empty, unparsable, or would remove most of the list) changes nothing.
/// </summary>
public sealed partial class BlocklistSyncer : IBlocklistSync
{
    private const long MaxDownloadBytes = 32 * 1024 * 1024;
    private readonly IBanStore _store;
    private readonly BanishOptions _options;
    private readonly AllowlistProvider _allowlist;
    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, SyncResult> _last = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (string? ETag, DateTimeOffset? LastModified)> _validators = new(StringComparer.OrdinalIgnoreCase);

    public BlocklistSyncer(
        IBanStore store,
        BanishOptions options,
        AllowlistProvider allowlist,
        HttpClient http,
        TimeProvider? time = null,
        ILogger? logger = null)
    {
        _store = store;
        _options = options;
        _allowlist = allowlist;
        _http = http;
        _time = time ?? TimeProvider.System;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    public IReadOnlyList<BlocklistSourceOptions> Sources => _options.Sync.Sources;

    public IReadOnlyList<SyncResult> LastResults
    {
        get
        {
            lock (_last)
            {
                return [.. _last.Values.OrderBy(r => r.Source, StringComparer.OrdinalIgnoreCase)];
            }
        }
    }

    public async Task<IReadOnlyList<SyncResult>> RunAllAsync(bool dryRun, CancellationToken cancellationToken)
    {
        var results = new List<SyncResult>();
        foreach (var source in Sources.Where(s => s.Enabled))
        {
            results.Add(await SyncAsync(source, dryRun, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    /// <summary>Syncs one source. Never throws for source problems; they are reported in the result.</summary>
    public async Task<SyncResult> SyncAsync(BlocklistSourceOptions source, bool dryRun, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var result = await SyncCoreAsync(source, dryRun, ct).ConfigureAwait(false);
            if (!dryRun)
            {
                lock (_last)
                {
                    _last[source.Name] = result;
                }
            }

            _logger.LogInformation(
                "Blocklist {Source}: {Status} (fetched {Fetched}, valid {Valid}, added {Added}, removed {Removed}){Message}",
                source.Name, result.Status, result.Fetched, result.Valid, result.Added, result.Removed,
                result.Message is null ? "" : " - " + result.Message);
            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<SyncResult> SyncCoreAsync(BlocklistSourceOptions source, bool dryRun, CancellationToken ct)
    {
        var started = _time.GetUtcNow().UtcDateTime;
        SyncResult Fail(string status, string message) => new(source.Name, started, status, 0, 0, 0, 0, 0, message);

        if (!SourceName().IsMatch(source.Name))
        {
            return Fail(SyncStatus.Error, "Source names may contain only letters, digits, '.', '_' and '-'.");
        }

        if (!Uri.TryCreate(source.Url, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && source.AllowInsecureHttp)))
        {
            return Fail(SyncStatus.Error, "The URL must be https (set AllowInsecureHttp to permit http).");
        }

        string text;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            foreach (var (name, value) in source.Headers)
            {
                request.Headers.TryAddWithoutValidation(name, value);
            }

            if (!dryRun && _validators.TryGetValue(source.Name, out var v))
            {
                if (v.ETag is not null)
                {
                    request.Headers.TryAddWithoutValidation("If-None-Match", v.ETag);
                }

                request.Headers.IfModifiedSince = v.LastModified;
            }

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                return Fail(SyncStatus.NotModified, "The list has not changed since the last download.");
            }

            if (!response.IsSuccessStatusCode)
            {
                return Fail(SyncStatus.Error, $"The server answered {(int)response.StatusCode} {response.ReasonPhrase}.");
            }

            text = await ReadLimitedAsync(response, ct).ConfigureAwait(false);
            if (!dryRun)
            {
                _validators[source.Name] = (response.Headers.ETag?.ToString(), response.Content.Headers.LastModified);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or InvalidDataException)
        {
            if (ct.IsCancellationRequested)
            {
                throw;
            }

            return Fail(SyncStatus.Error, ex.Message);
        }

        ParseResult parsed;
        try
        {
            parsed = BlocklistParser.Parse(text, source.Format, source.MaxEntries);
        }
        catch (Exception ex) when (ex is ArgumentException or System.Text.Json.JsonException)
        {
            return Fail(SyncStatus.Error, ex.Message);
        }

        await _allowlist.RefreshAsync(_store, ct).ConfigureAwait(false);
        var allow = _allowlist.Current;
        int skipped = parsed.Invalid;
        var valid = new List<string>(parsed.Addresses.Count);
        foreach (string address in parsed.Addresses)
        {
            if (IpAddressUtil.TryParseNetwork(address, out var network) && !allow.Overlaps(network))
            {
                valid.Add(address);
            }
            else
            {
                skipped++;
            }
        }

        string note = parsed.Truncated ? $"List cut off at MaxEntries ({source.MaxEntries})." : "";
        int fetched = parsed.Addresses.Count + parsed.Invalid;
        if (valid.Count == 0)
        {
            return new SyncResult(source.Name, started, SyncStatus.Refused, fetched, 0, skipped, 0, 0, "No usable addresses in the download; the existing entries were kept.");
        }

        string tag = BanSources.Blocklist(source.Name);
        var active = await _store.GetActiveAsync(ct).ConfigureAwait(false);
        var activeAll = active.Select(b => b.Address).ToHashSet(StringComparer.Ordinal);
        var current = active.Where(b => b.Source == tag).Select(b => b.Address).ToHashSet(StringComparer.Ordinal);
        var validSet = valid.ToHashSet(StringComparer.Ordinal);
        var toAdd = valid.Where(a => !activeAll.Contains(a)).ToList();
        int toRemove = current.Count(a => !validSet.Contains(a));

        if (current.Count >= 100 && toRemove * 100L > (long)current.Count * source.MaxRemovalPercent)
        {
            return new SyncResult(source.Name, started, SyncStatus.Refused, fetched, valid.Count, skipped, 0, 0,
                $"The refresh would lift {toRemove} of {current.Count} entries (more than {source.MaxRemovalPercent}%); nothing was changed.");
        }

        if (dryRun)
        {
            return new SyncResult(source.Name, started, SyncStatus.DryRun, fetched, valid.Count, skipped, toAdd.Count, toRemove, note.Length > 0 ? note : null);
        }

        var now = _time.GetUtcNow().UtcDateTime;
        int added = await _store.AddRangeAsync(
            toAdd.Select(a => new Ban
            {
                Address = a,
                Reason = $"on blocklist {source.Name}",
                Source = tag,
                CreatedUtc = now,
                ExpiresUtc = null,
                MachineName = _options.MachineName,
                CreatedBy = "sync",
            }).ToList(),
            ct).ConfigureAwait(false);
        int removed = toRemove == 0 ? 0 : await _store.RemoveBySourceAsync(tag, valid, "sync:" + source.Name, ct).ConfigureAwait(false);
        return new SyncResult(source.Name, started, SyncStatus.Ok, fetched, valid.Count, skipped, added, removed, note.Length > 0 ? note : null);
    }

    private static async Task<string> ReadLimitedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxDownloadBytes)
            {
                throw new InvalidDataException($"The download is larger than {MaxDownloadBytes / (1024 * 1024)} MB.");
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$")]
    private static partial Regex SourceName();
}
