using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Store.Api;

/// <summary>Raised when the Banish Web API rejects a request.</summary>
public sealed class BanishApiException(HttpStatusCode status, string message)
    : Exception($"Banish API returned {(int)status} {status}: {message}")
{
    public HttpStatusCode StatusCode { get; } = status;
}

/// <summary>IBanStore over the Banish Web API, for hosts that must not hold database credentials.</summary>
public sealed class HttpBanStore : IBanStore
{
    private static readonly System.Text.Json.JsonSerializerOptions Json = BanishJson.Options;
    private readonly HttpClient _http;

    public HttpBanStore(HttpClient http, string baseUrl, string apiKey)
    {
        _http = http;
        _http.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        _http.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task<Ban> AddAsync(Ban ban, CancellationToken cancellationToken) =>
        await SendAsync<Ban>(HttpMethod.Post, "api/v1/bans", ban, cancellationToken).ConfigureAwait(false)
        ?? throw new BanishApiException(HttpStatusCode.NoContent, "empty response");

    public async Task<int> RemoveAsync(string address, string removedBy, CancellationToken cancellationToken)
    {
        var result = await SendAsync<CountResponse>(
            HttpMethod.Delete,
            $"api/v1/bans?address={Uri.EscapeDataString(address)}&actor={Uri.EscapeDataString(removedBy)}",
            null,
            cancellationToken).ConfigureAwait(false);
        return result?.Count ?? 0;
    }

    public async Task<int> RemoveBySourceAsync(string source, IReadOnlyCollection<string> except, string removedBy, CancellationToken cancellationToken)
    {
        var result = await SendAsync<CountResponse>(
            HttpMethod.Post,
            "api/v1/bans/remove-by-source",
            new RemoveBySourceRequest(source, [.. except], removedBy),
            cancellationToken).ConfigureAwait(false);
        return result?.Count ?? 0;
    }

    public async Task<IReadOnlyList<Ban>> GetActiveAsync(CancellationToken cancellationToken) =>
        await SendAsync<List<Ban>>(HttpMethod.Get, "api/v1/bans/active", null, cancellationToken).ConfigureAwait(false) ?? [];

    public Task<Ban?> GetActiveByAddressAsync(string address, CancellationToken cancellationToken) =>
        SendAsync<Ban>(HttpMethod.Get, $"api/v1/bans/active/by-address?address={Uri.EscapeDataString(address)}", null, cancellationToken, notFoundIsNull: true);

    public async Task<int> CountPriorAsync(string address, CancellationToken cancellationToken)
    {
        var result = await SendAsync<CountResponse>(HttpMethod.Get, $"api/v1/bans/prior-count?address={Uri.EscapeDataString(address)}", null, cancellationToken).ConfigureAwait(false);
        return result?.Count ?? 0;
    }

    public async Task<PagedResult<Ban>> QueryAsync(BanQuery query, CancellationToken cancellationToken)
    {
        var parts = new List<string>
        {
            $"state={Uri.EscapeDataString(query.State)}",
            $"skip={query.Skip}",
            $"take={query.Take}",
        };
        void Add(string name, string? value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                parts.Add($"{name}={Uri.EscapeDataString(value)}");
            }
        }

        Add("search", query.Search);
        Add("source", query.Source);
        Add("rule", query.RuleId);
        Add("machine", query.MachineName);
        return await SendAsync<PagedResult<Ban>>(HttpMethod.Get, "api/v1/bans?" + string.Join('&', parts), null, cancellationToken).ConfigureAwait(false)
            ?? new PagedResult<Ban>([], 0);
    }

    public async Task<IReadOnlyList<BanEvent>> GetEventsAsync(int take, CancellationToken cancellationToken) =>
        await SendAsync<List<BanEvent>>(HttpMethod.Get, $"api/v1/events?take={take}", null, cancellationToken).ConfigureAwait(false) ?? [];

    public async Task<BanStats> GetStatsAsync(CancellationToken cancellationToken) =>
        await SendAsync<BanStats>(HttpMethod.Get, "api/v1/stats", null, cancellationToken).ConfigureAwait(false)
        ?? throw new BanishApiException(HttpStatusCode.NoContent, "empty response");

    public async Task<IReadOnlyList<AllowEntry>> GetAllowlistAsync(CancellationToken cancellationToken) =>
        await SendAsync<List<AllowEntry>>(HttpMethod.Get, "api/v1/allowlist", null, cancellationToken).ConfigureAwait(false) ?? [];

    public async Task<AllowEntry> AddAllowAsync(AllowEntry entry, CancellationToken cancellationToken) =>
        await SendAsync<AllowEntry>(HttpMethod.Post, "api/v1/allowlist", entry, cancellationToken).ConfigureAwait(false)
        ?? throw new BanishApiException(HttpStatusCode.NoContent, "empty response");

    public async Task<bool> RemoveAllowAsync(string address, CancellationToken cancellationToken)
    {
        var result = await SendAsync<CountResponse>(HttpMethod.Delete, $"api/v1/allowlist?address={Uri.EscapeDataString(address)}", null, cancellationToken).ConfigureAwait(false);
        return result?.Count > 0;
    }

    public async Task HeartbeatAsync(AgentInfo agent, CancellationToken cancellationToken) =>
        await SendAsync<object>(HttpMethod.Post, "api/v1/agents/heartbeat", agent, cancellationToken).ConfigureAwait(false);

    private async Task<T?> SendAsync<T>(HttpMethod method, string url, object? body, CancellationToken ct, bool notFoundIsNull = false)
        where T : class
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType(), options: Json);
        }

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (notFoundIsNull && response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        if (!response.IsSuccessStatusCode)
        {
            string text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new BanishApiException(response.StatusCode, text.Length > 300 ? text[..300] : text);
        }

        if (response.StatusCode == HttpStatusCode.NoContent || response.Content.Headers.ContentLength == 0)
        {
            return null;
        }

        return await response.Content.ReadFromJsonAsync<T>(Json, ct).ConfigureAwait(false);
    }
}

public sealed record CountResponse(int Count);

public sealed record RemoveBySourceRequest(string Source, List<string> Except, string? Actor);
