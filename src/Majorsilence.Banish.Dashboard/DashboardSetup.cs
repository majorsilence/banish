using System.Security.Claims;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Store.Ef;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Majorsilence.Banish.Dashboard;

public static class DashboardSetup
{
    public const string LoginRateLimitPolicy = "login";

    public static IServiceCollection AddBanishDashboard(this IServiceCollection services)
    {
        services.AddRazorComponents().AddInteractiveServerComponents();
        services.AddCascadingAuthenticationState();
        services.AddScoped<DashboardService>();
        services.AddSingleton<ChangeFeed>();
        services.AddHostedService<ChangeFeedBridge>();
        return services;
    }

    public static void MapBanishDashboard(this WebApplication app, BanishOptions options)
    {
        app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
        bool oidc = options.Auth.Mode.Equals(AuthModes.Oidc, StringComparison.OrdinalIgnoreCase);
        var account = app.MapGroup("/account").AllowAnonymous();

        account.MapGet("/login", (string? returnUrl) =>
            oidc
                ? Results.Challenge(new AuthenticationProperties { RedirectUri = SafeLocalUrl(returnUrl) }, [AuthSchemes.Oidc])
                : Results.Redirect("/login"));

        account.MapPost("/login", async (
            [FromForm] string? username,
            [FromForm] string? password,
            [FromForm] string? returnUrl,
            HttpContext http,
            UserService users) =>
        {
            string target = SafeLocalUrl(returnUrl);
            if (oidc)
            {
                return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, [AuthSchemes.Oidc]);
            }

            var user = string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)
                ? null
                : await users.ValidateAsync(username, password, http.RequestAborted);
            if (user is null)
            {
                return Results.Redirect("/login?error=1&returnUrl=" + Uri.EscapeDataString(target));
            }

            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.Name, user.UserName), new Claim(ClaimTypes.Role, user.Role)],
                AuthSchemes.Cookie);
            await http.SignInAsync(AuthSchemes.Cookie, new ClaimsPrincipal(identity));
            return Results.LocalRedirect(target);
        }).RequireRateLimiting(LoginRateLimitPolicy);

        account.MapPost("/logout", async (HttpContext http) =>
        {
            await http.SignOutAsync(AuthSchemes.Cookie);
            if (oidc)
            {
                return Results.SignOut(new AuthenticationProperties { RedirectUri = "/" }, [AuthSchemes.Oidc]);
            }

            return Results.LocalRedirect("/");
        });
    }

    /// <summary>Only same-site paths are honoured as a return address (no open redirect).</summary>
    public static string SafeLocalUrl(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl)
        && returnUrl[0] == '/'
        && (returnUrl.Length == 1 || (returnUrl[1] != '/' && returnUrl[1] != '\\'))
            ? returnUrl
            : "/";
}
