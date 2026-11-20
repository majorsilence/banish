using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Majorsilence.Banish.Api;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Dashboard;
using Majorsilence.Banish.Store.Ef;
using Majorsilence.Banish.Tests.Support;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Majorsilence.Banish.Tests;

public class IpMaskerTests
{
    [TestCase("203.0.113.5", "203.0.113.x")]
    [TestCase("198.51.100.0/24", "198.51.100.x/24")]
    [TestCase("2001:db8:1:2::9", "2001:db8:1:x")]
    [TestCase("2001:db8::/32", "2001:db8:x/32")]
    [TestCase("not-an-ip", "x")]
    public void MasksHostPart(string input, string expected) =>
        Assert.That(IpMasker.Mask(input), Is.EqualTo(expected));

    [Test]
    public void MaskingNeverMutatesTheOriginal()
    {
        var ban = new Ban { Address = "203.0.113.5", Reason = "r", Hits = 4 };
        var masked = IpMasker.Mask(ban);
        Assert.That(masked.Address, Is.EqualTo("203.0.113.x"));
        Assert.That(masked.Hits, Is.EqualTo(4));
        Assert.That(ban.Address, Is.EqualTo("203.0.113.5"));
    }
}

public class OidcRoleMapperTests
{
    private static readonly OidcOptions Options = new() { RoleClaim = "groups", AdminRoles = ["banish-admins"], ViewerRoles = ["banish-viewers", "staff"] };

    private static IReadOnlyList<string> Map(params (string Type, string Value)[] claims) =>
        OidcRoleMapper.Map(claims.Select(c => new Claim(c.Type, c.Value)), Options);

    [Test]
    public void AdminWinsOverViewer() =>
        Assert.That(Map(("groups", "staff"), ("groups", "banish-admins")), Is.EqualTo(new[] { ApiRoles.Admin }));

    [Test]
    public void ViewerRoleIsMapped() =>
        Assert.That(Map(("groups", "Staff")), Is.EqualTo(new[] { ApiRoles.Viewer }), "case is ignored");

    [Test]
    public void NoMatchMeansNoRole()
    {
        Assert.That(Map(("groups", "marketing")), Is.Empty);
        Assert.That(Map(("roles", "banish-admins")), Is.Empty, "only the configured claim counts");
        Assert.That(Map(), Is.Empty);
    }

    [Test]
    public void ArraysSentAsOneJsonStringAreExpanded() =>
        Assert.That(Map(("groups", "[\"x\",\"banish-admins\"]")), Is.EqualTo(new[] { ApiRoles.Admin }));
}

public class SafeLocalUrlTests
{
    [TestCase("/bans", "/bans")]
    [TestCase("/bans?state=all", "/bans?state=all")]
    [TestCase("/", "/")]
    [TestCase("//evil.example", "/")]
    [TestCase("/\\evil.example", "/")]
    [TestCase("https://evil.example", "/")]
    [TestCase("javascript:alert(1)", "/")]
    [TestCase("", "/")]
    [TestCase(null, "/")]
    public void OnlySameSitePathsAreHonoured(string? input, string expected) =>
        Assert.That(DashboardSetup.SafeLocalUrl(input), Is.EqualTo(expected));
}

public class UserServiceTests
{
    [Test]
    public async Task CreateValidateAndPasswordPolicy()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        await temp.CreateAsync();
        var users = new UserService(temp.Factory, clock);

        await users.CreateAsync("alice", "correct horse battery", ApiRoles.Admin, default);
        Assert.That((await users.ValidateAsync("alice", "correct horse battery", default))?.Role, Is.EqualTo(ApiRoles.Admin));
        Assert.That(await users.ValidateAsync("alice", "wrong horse battery", default), Is.Null);
        Assert.That(await users.ValidateAsync("nobody", "correct horse battery", default), Is.Null);
        Assert.That((await users.ListAsync(default)).Single().PasswordHash, Does.Not.Contain("correct horse"));

        await Assert.ThrowsAsync<ArgumentException>(() => users.CreateAsync("bob", "short", ApiRoles.Admin, default));
        await Assert.ThrowsAsync<ArgumentException>(() => users.CreateAsync("bob", "long enough password", "root", default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => users.CreateAsync("alice", "another long password", ApiRoles.Viewer, default));
    }

    [Test]
    public async Task RepeatedFailuresLockTheAccountThenItRecovers()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        await temp.CreateAsync();
        var users = new UserService(temp.Factory, clock);
        await users.CreateAsync("alice", "correct horse battery", ApiRoles.Admin, default);

        for (int i = 0; i < UserService.MaxFailedLogins; i++)
        {
            await users.ValidateAsync("alice", "wrong wrong wrong", default);
        }

        Assert.That(await users.ValidateAsync("alice", "correct horse battery", default), Is.Null, "locked even with the right password");
        clock.Advance(UserService.LockoutDuration + TimeSpan.FromSeconds(1));
        Assert.That(await users.ValidateAsync("alice", "correct horse battery", default), Is.Not.Null);
    }

    [Test]
    public async Task PasswordChangeAndDelete()
    {
        await using var temp = new TempStore();
        await temp.CreateAsync();
        var users = new UserService(temp.Factory);
        await users.CreateAsync("alice", "correct horse battery", ApiRoles.Viewer, default);

        Assert.That(await users.SetPasswordAsync("alice", "a brand new password", default), Is.True);
        Assert.That(await users.ValidateAsync("alice", "correct horse battery", default), Is.Null);
        Assert.That(await users.ValidateAsync("alice", "a brand new password", default), Is.Not.Null);
        Assert.That(await users.DeleteAsync("alice", default), Is.True);
        Assert.That(await users.DeleteAsync("alice", default), Is.False);
    }
}

public class DashboardServiceTests
{
    private sealed class FakeAuth(ClaimsPrincipal user) : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync() => Task.FromResult(new AuthenticationState(user));
    }

    private static ClaimsPrincipal User(string? role) =>
        role is null
            ? new ClaimsPrincipal(new ClaimsIdentity())
            : new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "pat"), new Claim(ClaimTypes.Role, role)], "test"));

    private static async Task<(DashboardService Service, TempStore Temp)> CreateAsync(string? role, bool mask = true)
    {
        var temp = new TempStore();
        var store = await temp.CreateAsync();
        await store.AddAsync(new Ban { Address = "203.0.113.5", Source = "manual", Reason = "x", Hits = 2 }, default);
        var options = new BanishOptions { Dashboard = new DashboardOptions { MaskIps = mask }, Allowlist = new AllowlistOptions { Entries = ["192.0.2.0/24"], IncludePrivateRanges = false } };
        return (new DashboardService(store, new FakeAuth(User(role)), options, new AllowlistProvider(options.Allowlist)), temp);
    }

    [TestCase(null)]
    [TestCase(ApiRoles.Viewer)]
    public async Task NonAdminsSeeMaskedAddressesEverywhere(string? role)
    {
        var (dash, temp) = await CreateAsync(role);
        await using (temp)
        {
            Assert.That((await dash.QueryAsync(new BanQuery())).Items.Single().Address, Is.EqualTo("203.0.113.x"));
            Assert.That((await dash.GetEventsAsync(10)).Single().Address, Is.EqualTo("203.0.113.x"));
            Assert.That((await dash.GetStatsAsync()).TopAddresses.Single().Key, Is.EqualTo("203.0.113.x"));
        }
    }

    [Test]
    public async Task AdminsSeeRealAddresses()
    {
        var (dash, temp) = await CreateAsync(ApiRoles.Admin);
        await using (temp)
        {
            Assert.That((await dash.QueryAsync(new BanQuery())).Items.Single().Address, Is.EqualTo("203.0.113.5"));
        }
    }

    [Test]
    public async Task MaskingCanBeTurnedOff()
    {
        var (dash, temp) = await CreateAsync(ApiRoles.Viewer, mask: false);
        await using (temp)
        {
            Assert.That((await dash.QueryAsync(new BanQuery())).Items.Single().Address, Is.EqualTo("203.0.113.5"));
        }
    }

    [TestCase(null)]
    [TestCase(ApiRoles.Viewer)]
    [TestCase(ApiRoles.Agent)]
    public async Task OnlyAdminsCanChangeAnything(string? role)
    {
        var (dash, temp) = await CreateAsync(role);
        await using (temp)
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => dash.BanAsync("203.0.113.9", null, null, false));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => dash.UnbanAsync("203.0.113.5"));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => dash.AddAllowAsync("203.0.113.9", null));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => dash.RemoveAllowAsync("203.0.113.9"));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => dash.GetAllowlistAsync());
            Assert.That((await dash.QueryAsync(new BanQuery())).Total, Is.EqualTo(1), "nothing changed");
        }
    }

    [Test]
    public async Task AdminCanBanAndUnbanWithGuardRails()
    {
        var (dash, temp) = await CreateAsync(ApiRoles.Admin);
        await using (temp)
        {
            Assert.That(await dash.BanAsync("203.0.113.9", "scanner", TimeSpan.FromHours(1), false), Is.Null);
            Assert.That(await dash.BanAsync("nonsense", null, null, false), Does.Contain("not an IP"));
            Assert.That(await dash.BanAsync("0.0.0.0/0", null, null, false), Does.Contain("cannot be banned"));
            Assert.That(await dash.BanAsync("192.0.2.77", null, null, false), Does.Contain("allow-listed"));
            Assert.That(await dash.BanAsync("192.0.2.77", null, null, true), Is.Null, "force overrides the allow-list");

            Assert.That(await dash.UnbanAsync("203.0.113.9"), Is.EqualTo(1));
            var bans = (await dash.QueryAsync(new BanQuery())).Items;
            Assert.That(bans.Select(b => b.Address), Is.EquivalentTo(new[] { "203.0.113.5", "192.0.2.77" }));
            Assert.That(bans.First(b => b.Address == "192.0.2.77").CreatedBy, Is.EqualTo("pat"));

            Assert.That(await dash.AddAllowAsync("198.51.100.0/24", "office"), Is.Null);
            Assert.That(await dash.AddAllowAsync("bogus", null), Does.Contain("not an IP"));
            Assert.That((await dash.GetAllowlistAsync()).Single().Address, Is.EqualTo("198.51.100.0/24"));
            await dash.RemoveAllowAsync("198.51.100.0/24");
            Assert.That(await dash.GetAllowlistAsync(), Is.Empty);
        }
    }
}

/// <summary>The dashboard over real HTTP: sign-in, cookies, antiforgery, public mode and masking.</summary>
public class DashboardHttpTests
{
    private string _dir = "";
    private WebApplication _app = null!;
    private string _url = "";

    [SetUp]
    public async Task SetUp()
    {
        _dir = Path.Combine(Path.GetTempPath(), "banish-dash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        await StartAsync(publicReadOnly: false);
    }

    private async Task StartAsync(bool publicReadOnly)
    {
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }

        var options = new BanishOptions
        {
            MachineName = "central",
            Store = new StoreOptions { Provider = StoreProviders.Sqlite, ConnectionString = $"Data Source={Path.Combine(_dir, "d.db")}" },
            Api = new ApiOptions { Urls = "http://127.0.0.1:0" },
            Dashboard = new DashboardOptions { PublicReadOnly = publicReadOnly, MaskIps = true },
            Rules = [],
        };
        _app = ApiHost.Build(options, ["--environment", "Development"]);
        await _app.StartAsync();
        var store = _app.Services.GetRequiredService<EfBanStore>();
        await store.MigrateAsync(default);
        _url = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        var users = _app.Services.GetRequiredService<UserService>();
        if ((await users.ListAsync(default)).Count == 0)
        {
            await users.CreateAsync("admin", "an admin password 1", ApiRoles.Admin, default);
            await users.CreateAsync("viewer", "a viewer password 1", ApiRoles.Viewer, default);
            await store.AddAsync(new Ban { Address = "203.0.113.5", Source = "manual", Reason = "scan", CreatedUtc = DateTime.UtcNow }, default);
        }
    }

    [TearDown]
    public async Task TearDown()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _app = null!;
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, true);
    }

    private (HttpClient Client, CookieContainer Cookies) NewBrowser()
    {
        var cookies = new CookieContainer();
        var handler = new HttpClientHandler { CookieContainer = cookies, AllowAutoRedirect = false };
        return (new HttpClient(handler) { BaseAddress = new Uri(_url) }, cookies);
    }

    private static async Task<string> TokenAsync(HttpClient client)
    {
        string html = await client.GetStringAsync("/login");
        return Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
    }

    private static async Task<HttpResponseMessage> LoginAsync(HttpClient client, string user, string password, string returnUrl = "/")
    {
        string token = await TokenAsync(client);
        return await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = user,
            ["password"] = password,
            ["returnUrl"] = returnUrl,
            ["__RequestVerificationToken"] = token,
        }));
    }

    [Test]
    public async Task AnonymousVisitorIsSentToTheLoginPage()
    {
        var (client, _) = NewBrowser();
        var response = await client.GetAsync("/");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location!.ToString(), Does.Contain("/login"));
    }

    [Test]
    public async Task AdminSignsInAndSeesRealAddressesAndControls()
    {
        var (client, _) = NewBrowser();
        var login = await LoginAsync(client, "admin", "an admin password 1", "/bans");
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(login.Headers.Location!.ToString(), Is.EqualTo("/bans"));

        string page = await client.GetStringAsync("/bans");
        Assert.That(page, Does.Contain("203.0.113.5").And.Contain("Ban an address").And.Contain("Unban"));
        Assert.That((await client.GetAsync("/allowlist")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        string home = await client.GetStringAsync("/");
        Assert.That(home, Does.Contain("Active bans").And.Contain("<svg"));
    }

    [Test]
    public async Task ViewerSeesMaskedAddressesAndNoAdminControls()
    {
        var (client, _) = NewBrowser();
        await LoginAsync(client, "viewer", "a viewer password 1");

        string page = await client.GetStringAsync("/bans");
        Assert.That(page, Does.Contain("203.0.113.x").And.Not.Contain("203.0.113.5"));
        Assert.That(page, Does.Not.Contain("Ban an address").And.Not.Contain(">Unban<"));
        var allow = await client.GetAsync("/allowlist");
        Assert.That(allow.StatusCode, Is.Not.EqualTo(HttpStatusCode.OK), "admin pages stay closed to viewers");
    }

    [Test]
    public async Task WrongPasswordAndMissingAntiforgeryTokenAreRefused()
    {
        var (client, _) = NewBrowser();
        var wrong = await LoginAsync(client, "admin", "not the password!!");
        Assert.That(wrong.Headers.Location!.ToString(), Does.StartWith("/login?error=1"));
        Assert.That((await client.GetAsync("/bans")).StatusCode, Is.EqualTo(HttpStatusCode.Redirect), "still signed out");

        var forged = await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = "admin",
            ["password"] = "an admin password 1",
        }));
        Assert.That(forged.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task ReturnUrlCannotLeaveTheSite()
    {
        var (client, _) = NewBrowser();
        var login = await LoginAsync(client, "admin", "an admin password 1", "//evil.example/steal");
        Assert.That(login.Headers.Location!.ToString(), Is.EqualTo("/"));
    }

    [Test]
    public async Task SigningOutEndsTheSession()
    {
        var (client, _) = NewBrowser();
        await LoginAsync(client, "admin", "an admin password 1");
        Assert.That((await client.GetAsync("/bans")).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        string token = await TokenAsync(client);
        await client.PostAsync("/account/logout", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }));
        Assert.That((await client.GetAsync("/bans")).StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    [Test]
    public async Task PublicReadOnlyShowsMaskedViewsWithoutSigningIn()
    {
        await StartAsync(publicReadOnly: true);
        var (client, _) = NewBrowser();

        string home = await client.GetStringAsync("/");
        Assert.That(home, Does.Contain("Active bans"));
        string bans = await client.GetStringAsync("/bans");
        Assert.That(bans, Does.Contain("203.0.113.x").And.Not.Contain("203.0.113.5").And.Not.Contain("Ban an address"));
        Assert.That((await client.GetAsync("/allowlist")).StatusCode, Is.EqualTo(HttpStatusCode.Redirect), "admin pages still need a sign-in");
    }

    [Test]
    public async Task BlazorFrameworkScriptIsServed()
    {
        var (client, _) = NewBrowser();
        var script = await client.GetAsync("/_framework/blazor.web.js");
        Assert.That(script.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task OidcModeRequiresAnAuthorityAndOffersOrganizationSignIn()
    {
        var bad = new BanishOptions
        {
            Store = new StoreOptions { Provider = StoreProviders.Sqlite, ConnectionString = $"Data Source={Path.Combine(_dir, "o.db")}" },
            Api = new ApiOptions { Urls = "http://127.0.0.1:0" },
            Auth = new AuthOptions { Mode = AuthModes.Oidc },
            Rules = [],
        };
        Assert.That(() => ApiHost.Build(bad, []), Throws.InvalidOperationException.With.Message.Contains("Authority"));

        bad.Auth.Oidc = new OidcOptions { Authority = "https://idp.example.test", ClientId = "banish", AdminRoles = ["admins"] };
        await using var app = ApiHost.Build(bad, []);
        await app.StartAsync();
        string url = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        string login = await new HttpClient().GetStringAsync(url + "/login");
        Assert.That(login, Does.Contain("Sign in with your organization account").And.Not.Contain("name=\"password\""));
        await app.StopAsync();
    }
}
