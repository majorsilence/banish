using System.Security.Claims;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Dashboard;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Majorsilence.Banish.Api;

/// <summary>
/// Authentication for the two kinds of caller: agents and scripts present an API key; people use a
/// cookie obtained from the local login form or from an OpenID Connect provider. A policy scheme
/// picks by request, so <c>/api</c> calls without a key get a plain 401 rather than a login redirect.
/// </summary>
internal static class ApiAuth
{
    public static void Configure(IServiceCollection services, BanishOptions options, bool oidc)
    {
        var auth = services.AddAuthentication(AuthSchemes.Smart)
            .AddPolicyScheme(AuthSchemes.Smart, AuthSchemes.Smart, o =>
            {
                // /api answers with 401/403; the dashboard uses the cookie (whose challenge redirects to /login).
                o.ForwardDefaultSelector = ctx => HasApiKey(ctx.Request) || IsApi(ctx.Request) ? AuthSchemes.ApiKey : AuthSchemes.Cookie;
            })
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(AuthSchemes.ApiKey, _ => { })
            .AddCookie(AuthSchemes.Cookie, o =>
            {
                o.LoginPath = "/login";
                o.AccessDeniedPath = "/login";
                o.Cookie.Name = "banish.auth";
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                o.ExpireTimeSpan = TimeSpan.FromHours(8);
                o.SlidingExpiration = true;
            });

        if (oidc)
        {
            var settings = options.Auth.Oidc;
            auth.AddOpenIdConnect(AuthSchemes.Oidc, o =>
            {
                o.SignInScheme = AuthSchemes.Cookie;
                o.Authority = settings.Authority;
                o.ClientId = settings.ClientId;
                o.ClientSecret = settings.ClientSecret;
                o.RequireHttpsMetadata = settings.RequireHttpsMetadata;
                o.ResponseType = "code";
                o.UsePkce = true;
                o.SaveTokens = false;
                o.MapInboundClaims = false;
                o.GetClaimsFromUserInfoEndpoint = true;
                o.Scope.Clear();
                foreach (string scope in new[] { "openid", "profile" }.Concat(settings.Scopes).Distinct())
                {
                    o.Scope.Add(scope);
                }

                o.TokenValidationParameters.NameClaimType = "name";
                o.CallbackPath = "/signin-oidc";
                o.Events = new OpenIdConnectEvents
                {
                    // After the provider's claims are in, translate its roles/groups into Banish roles.
                    // No match means no role, which means no access.
                    OnTicketReceived = ctx =>
                    {
                        if (ctx.Principal?.Identity is ClaimsIdentity identity)
                        {
                            foreach (string role in OidcRoleMapper.Map(identity.Claims, settings))
                            {
                                identity.AddClaim(new Claim(ClaimTypes.Role, role));
                            }

                            if (identity.Name is null && identity.FindFirst("preferred_username") is { } name)
                            {
                                identity.AddClaim(new Claim("name", name.Value));
                            }
                        }

                        return Task.CompletedTask;
                    },
                };
            });
        }

        services.AddAuthorizationBuilder()
            .AddPolicy(Policies.Agent, p => p.RequireRole(ApiRoles.Agent, ApiRoles.Admin))
            .AddPolicy(Policies.Admin, p => p.RequireRole(ApiRoles.Admin))
            .AddPolicy(Policies.Viewer, p => p.RequireAssertion(ctx =>
                options.Dashboard.PublicReadOnly
                || ctx.User.IsInRole(ApiRoles.Viewer)
                || ctx.User.IsInRole(ApiRoles.Admin)
                || ctx.User.IsInRole(ApiRoles.Agent)));
    }

    private static bool IsApi(HttpRequest request) => request.Path.StartsWithSegments("/api");

    private static bool HasApiKey(HttpRequest request) =>
        request.Headers.ContainsKey("X-Api-Key")
        || request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
}
