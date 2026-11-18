using System.Security.Claims;
using System.Text.Encodings.Web;
using Majorsilence.Banish.Store.Ef;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Majorsilence.Banish.Api;

public static class ApiKeyDefaults
{
    public const string Scheme = Majorsilence.Banish.Core.AuthSchemes.ApiKey;
}

/// <summary>Authenticates <c>Authorization: Bearer bnk_...</c> (or <c>X-Api-Key</c>) against stored key hashes.</summary>
public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ApiKeyService _keys;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ApiKeyService keys)
        : base(options, logger, encoder)
    {
        _keys = keys;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? key = null;
        string header = Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            key = header["Bearer ".Length..].Trim();
        }
        else if (Request.Headers.TryGetValue("X-Api-Key", out var apiKey))
        {
            key = apiKey.ToString();
        }

        if (key is null)
        {
            return AuthenticateResult.NoResult();
        }

        var entry = await _keys.ValidateAsync(key, Context.RequestAborted).ConfigureAwait(false);
        if (entry is null)
        {
            return AuthenticateResult.Fail("Invalid API key");
        }

        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, entry.Name), new Claim(ClaimTypes.Role, entry.Role), new Claim("auth", "apikey")],
            ApiKeyDefaults.Scheme);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), ApiKeyDefaults.Scheme));
    }
}
