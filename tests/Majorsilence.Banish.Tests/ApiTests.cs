using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Majorsilence.Banish.Api;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Store.Api;
using Majorsilence.Banish.Store.Ef;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Majorsilence.Banish.Tests;

public class ApiTests
{
    private string _dir = "";
    private WebApplication _app = null!;
    private string _url = "";
    private string _agentKey = "";
    private string _adminKey = "";

    [SetUp]
    public async Task SetUp()
    {
        _dir = Path.Combine(Path.GetTempPath(), "banish-api-" + Guid.NewGuid().ToString("N"));
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
            Store = new StoreOptions { Provider = StoreProviders.Sqlite, ConnectionString = $"Data Source={Path.Combine(_dir, "api.db")}" },
            Api = new ApiOptions { Urls = "http://127.0.0.1:0" },
            Allowlist = new AllowlistOptions { Entries = ["203.0.113.99"], IncludePrivateRanges = false },
            Dashboard = new DashboardOptions { PublicReadOnly = publicReadOnly },
            Rules = [new RuleOptions { Name = "webapp", Detector = "Http", MaxRetry = 2, BanMinutes = [10] }],
        };
        _app = ApiHost.Build(options, []);
        await _app.StartAsync();
        await _app.Services.GetRequiredService<EfBanStore>().MigrateAsync(default);
        _url = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        var keys = _app.Services.GetRequiredService<ApiKeyService>();
        if ((await keys.ListAsync(default)).Count == 0)
        {
            _agentKey = (await keys.CreateAsync("web-01", ApiRoles.Agent, default)).Key;
            _adminKey = (await keys.CreateAsync("ops", ApiRoles.Admin, default)).Key;
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

    private HttpBanStore Client(string key) => new(new HttpClient(), _url, key);

    private static Ban NewBan(string address) => new() { Address = address, Reason = "test", Source = "manual", MachineName = "spoofed", ExpiresUtc = DateTime.UtcNow.AddHours(1), Hits = 1 };

    [Test]
    public async Task AgentReportsBanAndOtherAgentReadsIt()
    {
        var agent = Client(_agentKey);
        var saved = await agent.AddAsync(NewBan("203.0.113.5"), default);

        Assert.That(saved.MachineName, Is.EqualTo("web-01"), "an agent speaks only for itself");
        Assert.That(saved.Source, Is.EqualTo(BanSources.Local), "an agent cannot claim manual bans");
        var active = await Client(_adminKey).GetActiveAsync(default);
        Assert.That(active.Select(b => b.Address), Is.EqualTo(new[] { "203.0.113.5" }));
        Assert.That(await agent.GetActiveByAddressAsync("203.0.113.5", default), Is.Not.Null);
        Assert.That(await agent.GetActiveByAddressAsync("203.0.113.6", default), Is.Null);
        Assert.That(await agent.CountPriorAsync("203.0.113.5", default), Is.EqualTo(1));
    }

    [Test]
    public async Task AgentCannotUnbanOrEditAllowlist()
    {
        await Client(_adminKey).AddAsync(NewBan("203.0.113.5"), default);
        var agent = Client(_agentKey);

        var unban = await Assert.ThrowsAsync<BanishApiException>(() => agent.RemoveAsync("203.0.113.5", "x", default));
        Assert.That(unban!.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        await Assert.ThrowsAsync<BanishApiException>(() => agent.AddAllowAsync(new AllowEntry { Address = "1.2.3.4" }, default));
        await Assert.ThrowsAsync<BanishApiException>(() => agent.RemoveBySourceAsync("blocklist:x", [], "x", default));
        Assert.That(await Client(_adminKey).GetActiveAsync(default), Has.Count.EqualTo(1));
    }

    [Test]
    public async Task AdminCanBanUnbanAndManageAllowlist()
    {
        var admin = Client(_adminKey);
        var ban = await admin.AddAsync(NewBan("198.51.100.0/24"), default);
        Assert.That(ban.Source, Is.EqualTo("manual"));
        Assert.That(ban.CreatedBy, Is.EqualTo("ops"));

        Assert.That(await admin.RemoveAsync("198.51.100.0/24", "alice", default), Is.EqualTo(1));
        var events = await admin.GetEventsAsync(5, default);
        Assert.That(events[0].Actor, Is.EqualTo("ops/alice"));

        await admin.AddAllowAsync(new AllowEntry { Address = "192.0.2.0/24", Note = "office" }, default);
        Assert.That((await Client(_agentKey).GetAllowlistAsync(default)).Select(a => a.Address), Does.Contain("192.0.2.0/24"));
        Assert.That(await admin.RemoveAllowAsync("192.0.2.0/24", default), Is.True);
    }

    [Test]
    public async Task BadOrMissingKeysAreRejected()
    {
        var none = new HttpClient();
        var response = await none.GetAsync(_url + "/api/v1/bans/active");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

        var bad = Client("bnk_notAValidKey");
        var ex = await Assert.ThrowsAsync<BanishApiException>(() => bad.GetActiveAsync(default));
        Assert.That(ex!.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task RevokedKeyStopsWorking()
    {
        var keys = _app.Services.GetRequiredService<ApiKeyService>();
        Assert.That(await keys.RevokeAsync("web-01", default), Is.True);
        await Assert.ThrowsAsync<BanishApiException>(() => Client(_agentKey).GetActiveAsync(default));
    }

    [Test]
    public async Task InvalidAndAllowListedAddressesAreRefused()
    {
        var agent = Client(_agentKey);
        var bad = await Assert.ThrowsAsync<BanishApiException>(() => agent.AddAsync(NewBan("not-an-ip"), default));
        Assert.That(bad!.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        await Assert.ThrowsAsync<BanishApiException>(() => agent.AddAsync(NewBan("0.0.0.0/0"), default));

        var allowed = await Assert.ThrowsAsync<BanishApiException>(() => agent.AddAsync(NewBan("203.0.113.99"), default));
        Assert.That(allowed!.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        await Task.CompletedTask;
    }

    [Test]
    public async Task HeartbeatIsRecordedUnderTheKeysName()
    {
        await Client(_agentKey).HeartbeatAsync(new AgentInfo { MachineName = "spoofed", Os = "Linux", AppliedBans = 3, StartedUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow }, default);

        var stats = await Client(_adminKey).GetStatsAsync(default);
        Assert.That(stats.Agents.Select(a => a.MachineName), Is.EqualTo(new[] { "web-01" }));
        Assert.That(stats.Agents[0].AppliedBans, Is.EqualTo(3));
    }

    [Test]
    public async Task FailureReportsAreCountedByTheCentralEngine()
    {
        var http = new HttpClient { BaseAddress = new Uri(_url) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _agentKey);

        var first = await http.PostAsJsonAsync("/api/v1/failures", new { address = "203.0.113.20", rule = "webapp" });
        Assert.That(await first.Content.ReadAsStringAsync(), Does.Contain("\"banned\":false"));
        var second = await http.PostAsJsonAsync("/api/v1/failures", new { address = "203.0.113.20", rule = "webapp" });
        Assert.That(await second.Content.ReadAsStringAsync(), Does.Contain("\"banned\":true"));

        Assert.That((await Client(_adminKey).GetActiveAsync(default)).Select(b => b.Address), Is.EqualTo(new[] { "203.0.113.20" }));
        Assert.That((await http.PostAsJsonAsync("/api/v1/failures", new { address = "x", rule = "webapp" })).StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task QueryStatsAndBlocklistExport()
    {
        var admin = Client(_adminKey);
        await admin.AddAsync(NewBan("203.0.113.1"), default);
        await admin.AddAsync(NewBan("203.0.113.2"), default);

        var page = await Client(_agentKey).QueryAsync(new BanQuery { Search = "113.2" }, default);
        Assert.That(page.Total, Is.EqualTo(1));
        Assert.That((await admin.GetStatsAsync(default)).ActiveBans, Is.EqualTo(2));

        var http = new HttpClient { BaseAddress = new Uri(_url) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _adminKey);
        Assert.That(await http.GetStringAsync("/api/v1/blocklist.txt"), Is.EqualTo("203.0.113.1\n203.0.113.2\n"));
    }

    [Test]
    public async Task PublicReadOnlyAllowsAnonymousViewingButNotWriting()
    {
        var anon = new HttpClient { BaseAddress = new Uri(_url) };
        Assert.That((await anon.GetAsync("/api/v1/stats")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

        await StartAsync(publicReadOnly: true);
        anon = new HttpClient { BaseAddress = new Uri(_url) };
        Assert.That((await anon.GetAsync("/api/v1/stats")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await anon.GetAsync("/api/v1/bans/active")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That((await anon.PostAsJsonAsync("/api/v1/bans", NewBan("203.0.113.7"))).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task HealthIsAnonymous()
    {
        Assert.That((await new HttpClient().GetAsync(_url + "/api/v1/health")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task ApiKeyServiceNeverStoresThePlainKey()
    {
        var keys = _app.Services.GetRequiredService<ApiKeyService>();
        var listed = await keys.ListAsync(default);

        Assert.That(listed.Select(k => k.KeyHash), Does.Not.Contain(_agentKey));
        Assert.That(listed.All(k => k.KeyHash.Length == 64), Is.True);
        Assert.That(_agentKey, Does.StartWith("bnk_"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => keys.CreateAsync("web-01", ApiRoles.Agent, default));
    }

    [Test]
    public async Task BanDetectedOnOneAgentIsEnforcedOnAnotherThroughTheApi()
    {
        var keys = _app.Services.GetRequiredService<ApiKeyService>();
        string keyB = (await keys.CreateAsync("web-02", ApiRoles.Agent, default)).Key;
        var storeA = Client(_agentKey);
        var storeB = Client(keyB);
        var noAllow = Allowlist.Create([], false, false);

        // Agent A's engine sees repeated failures and bans through the API.
        var engineA = new BanEngine(storeA, [new RuleOptions { Name = "sshd", MaxRetry = 2 }], () => noAllow, "web-01");
        var failure = new FailureEvent(System.Net.IPAddress.Parse("203.0.113.77"), "sshd", DateTime.UtcNow);
        await engineA.ReportFailureAsync(failure, default);
        Assert.That(await engineA.ReportFailureAsync(failure, default), Is.Not.Null);

        // Agent B has seen nothing locally, yet its reconcile loop blocks the address.
        var firewallB = new RecordingFirewall();
        var reconcilerB = new FirewallReconciler(storeB, firewallB, () => noAllow);
        Assert.That(await reconcilerB.ReconcileAsync(default), Is.True);
        Assert.That(firewallB.Last, Is.EqualTo(new[] { "203.0.113.77" }));

        // An admin lifts the ban centrally; B follows on its next pass.
        await Client(_adminKey).RemoveAsync("203.0.113.77", "ops", default);
        Assert.That(await reconcilerB.ReconcileAsync(default), Is.True);
        Assert.That(firewallB.Last, Is.Empty);
    }

    private sealed class RecordingFirewall : IFirewall
    {
        public string[] Last { get; private set; } = [];

        public string Name => "recording";

        public Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken)
        {
            Last = [.. addresses];
            return Task.CompletedTask;
        }

        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
