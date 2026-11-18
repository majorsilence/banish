using System.Net;
using Majorsilence.Banish.Cli;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Store.Ef;
using Majorsilence.Banish.Sync;
using Majorsilence.Banish.Tests.Support;

namespace Majorsilence.Banish.Tests;

public class BlocklistParserTests
{
    [Test]
    public void PlainHandlesCommentsAndTrailingNotes()
    {
        const string text = """
            ; Spamhaus DROP List
            # a comment
            1.10.16.0/20 ; SBL256894
            1.19.0.0/16 ; SBL434604

            203.0.113.5
            2001:db8::/32 # v6
            203.0.113.5
            """;
        var result = BlocklistParser.Parse(text, "plain", 100);

        Assert.That(result.Addresses, Is.EqualTo(new[] { "1.10.16.0/20", "1.19.0.0/16", "203.0.113.5", "2001:db8::/32" }), "duplicates collapse");
        Assert.That(result.Invalid, Is.EqualTo(0));
    }

    [Test]
    public void InvalidAndUnbannableEntriesAreCountedNotImported()
    {
        var result = BlocklistParser.Parse("203.0.113.5\nnot-an-ip\n0.0.0.0/0\n1.2.3\n224.0.0.1\n10.0.0.0/4", "plain", 100);
        Assert.That(result.Addresses, Is.EqualTo(new[] { "203.0.113.5" }));
        Assert.That(result.Invalid, Is.EqualTo(5));
    }

    [Test]
    public void MaxEntriesTruncates()
    {
        string text = string.Join('\n', Enumerable.Range(1, 50).Select(i => $"203.0.113.{i}"));
        var result = BlocklistParser.Parse(text, "plain", 10);
        Assert.That(result.Addresses, Has.Count.EqualTo(10));
        Assert.That(result.Truncated, Is.True);
    }

    [Test]
    public void CsvSkipsHeaderAndUsesFirstColumn()
    {
        var result = BlocklistParser.Parse("ip,country\n203.0.113.5,US\n\"198.51.100.0/24\",DE\n", "csv", 100);
        Assert.That(result.Addresses, Is.EqualTo(new[] { "203.0.113.5", "198.51.100.0/24" }));
        Assert.That(result.Invalid, Is.EqualTo(0));
    }

    [Test]
    public void JsonArrayOfStringsAndObjects()
    {
        var result = BlocklistParser.Parse("""["203.0.113.5", {"cidr":"198.51.100.0/24","rir":"x"}, {"ip":"2001:db8::1"}, 7]""", "json", 100);
        Assert.That(result.Addresses, Is.EqualTo(new[] { "203.0.113.5", "198.51.100.0/24", "2001:db8::1" }));
    }

    [Test]
    public void JsonOneObjectPerLineLikeSpamhausDrop()
    {
        const string text = "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\"}\n{\"cidr\":\"1.19.0.0/16\",\"sblid\":\"SBL434604\"}\n";
        Assert.That(BlocklistParser.Parse(text, "json", 100).Addresses, Is.EqualTo(new[] { "1.10.16.0/20", "1.19.0.0/16" }));
    }

    [Test]
    public void UnknownFormatIsAnError() =>
        Assert.Throws<ArgumentException>(() => BlocklistParser.Parse("x", "xml", 10));
}

public class BlocklistSyncerTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        public string Body { get; set; } = "";
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
        public string? ETag { get; set; }
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (ETag is not null && request.Headers.IfNoneMatch.Any(t => t.Tag == ETag))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
            }

            var response = new HttpResponseMessage(Status) { Content = new StringContent(Body) };
            if (ETag is not null)
            {
                response.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue(ETag);
            }

            return Task.FromResult(response);
        }
    }

    private sealed record Rig(TempStore Temp, EfBanStore Store, FakeHandler Http, BlocklistSyncer Syncer, BlocklistSourceOptions Source) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => Temp.DisposeAsync();
    }

    private static async Task<Rig> CreateAsync(string body, Action<BlocklistSourceOptions>? tweak = null, params string[] allow)
    {
        var temp = new TempStore();
        var store = await temp.CreateAsync();
        var options = new BanishOptions
        {
            MachineName = "sync-host",
            Allowlist = new AllowlistOptions { Entries = [.. allow], IncludePrivateRanges = true },
        };
        var source = new BlocklistSourceOptions { Name = "drop", Url = "https://lists.example.test/drop.txt" };
        tweak?.Invoke(source);
        options.Sync.Sources.Add(source);
        var http = new FakeHandler { Body = body };
        var syncer = new BlocklistSyncer(store, options, new AllowlistProvider(options.Allowlist), new HttpClient(http));
        return new Rig(temp, store, http, syncer, source);
    }

    [Test]
    public async Task AddsNewEntriesAndLiftsOnesThatLeftTheList()
    {
        await using var rig = await CreateAsync("203.0.113.1\n203.0.113.2\n203.0.113.3\n");
        var first = await rig.Syncer.SyncAsync(rig.Source, false, default);
        Assert.That((first.Status, first.Added, first.Removed), Is.EqualTo((SyncStatus.Ok, 3, 0)));

        rig.Http.Body = "203.0.113.2\n203.0.113.3\n203.0.113.4\n";
        var second = await rig.Syncer.SyncAsync(rig.Source, false, default);

        Assert.That((second.Added, second.Removed), Is.EqualTo((1, 1)));
        var active = await rig.Store.GetActiveAsync(default);
        Assert.That(active.Select(b => b.Address), Is.EquivalentTo(new[] { "203.0.113.2", "203.0.113.3", "203.0.113.4" }));
        Assert.That(active.All(b => b.Source == "blocklist:drop" && b.ExpiresUtc is null), Is.True);
        Assert.That((await rig.Store.QueryAsync(new BanQuery { State = "removed" }, default)).Items.Single().RemovedBy, Is.EqualTo("sync:drop"));
    }

    [Test]
    public async Task AllowListedAndPrivateEntriesAreNeverImported()
    {
        await using var rig = await CreateAsync("203.0.113.1\n198.51.100.0/24\n10.0.0.0/8\n192.168.1.1\n127.0.0.1\n", null, "198.51.100.7");
        var result = await rig.Syncer.SyncAsync(rig.Source, false, default);

        Assert.That((await rig.Store.GetActiveAsync(default)).Select(b => b.Address), Is.EqualTo(new[] { "203.0.113.1" }));
        Assert.That(result.Skipped, Is.EqualTo(4), "a range containing an allow-listed address is skipped too");
    }

    [Test]
    public async Task EntriesAlreadyBannedByOtherSourcesAreNotDuplicated()
    {
        await using var rig = await CreateAsync("203.0.113.1\n203.0.113.2\n");
        await rig.Store.AddAsync(new Ban { Address = "203.0.113.1", Source = BanSources.Local, Reason = "ssh", CreatedUtc = DateTime.UtcNow }, default);

        var result = await rig.Syncer.SyncAsync(rig.Source, false, default);

        Assert.That(result.Added, Is.EqualTo(1));
        Assert.That(await rig.Store.GetActiveAsync(default), Has.Count.EqualTo(2));
    }

    [Test]
    public async Task EmptyOrUnparsableDownloadChangesNothing()
    {
        await using var rig = await CreateAsync("203.0.113.1\n203.0.113.2\n");
        await rig.Syncer.SyncAsync(rig.Source, false, default);

        rig.Http.Body = "<html>Rate limited</html>";
        var result = await rig.Syncer.SyncAsync(rig.Source, false, default);

        Assert.That(result.Status, Is.EqualTo(SyncStatus.Refused));
        Assert.That(await rig.Store.GetActiveAsync(default), Has.Count.EqualTo(2));
    }

    [Test]
    public async Task ARefreshThatWouldDropMostOfTheListIsRefused()
    {
        string big = string.Join('\n', Enumerable.Range(1, 200).Select(i => $"203.0.{i / 250}.{i % 250 + 1}"));
        await using var rig = await CreateAsync(big);
        await rig.Syncer.SyncAsync(rig.Source, false, default);

        rig.Http.Body = "203.0.0.2\n203.0.0.3\n";
        var result = await rig.Syncer.SyncAsync(rig.Source, false, default);

        Assert.That(result.Status, Is.EqualTo(SyncStatus.Refused));
        Assert.That(result.Message, Does.Contain("198 of 200"));
        Assert.That(await rig.Store.GetActiveAsync(default), Has.Count.EqualTo(200));
    }

    [Test]
    public async Task DryRunReportsWithoutChangingAnything()
    {
        await using var rig = await CreateAsync("203.0.113.1\n203.0.113.2\n");
        var result = await rig.Syncer.SyncAsync(rig.Source, true, default);

        Assert.That((result.Status, result.Added), Is.EqualTo((SyncStatus.DryRun, 2)));
        Assert.That(await rig.Store.GetActiveAsync(default), Is.Empty);
        Assert.That(rig.Syncer.LastResults, Is.Empty, "a preview is not recorded as a sync");
    }

    [Test]
    public async Task UnchangedListIsNotDownloadedAgain()
    {
        await using var rig = await CreateAsync("203.0.113.1\n");
        rig.Http.ETag = "\"v1\"";
        await rig.Syncer.SyncAsync(rig.Source, false, default);

        var again = await rig.Syncer.SyncAsync(rig.Source, false, default);

        Assert.That(again.Status, Is.EqualTo(SyncStatus.NotModified));
        Assert.That(rig.Http.Requests, Has.Count.EqualTo(2));
        Assert.That(await rig.Store.GetActiveAsync(default), Has.Count.EqualTo(1));
    }

    [Test]
    public async Task PlainHttpAndBadNamesAreRejectedUnlessAllowed()
    {
        await using var rig = await CreateAsync("203.0.113.1\n", s => s.Url = "http://lists.example.test/drop.txt");
        Assert.That((await rig.Syncer.SyncAsync(rig.Source, false, default)).Status, Is.EqualTo(SyncStatus.Error));
        Assert.That(rig.Http.Requests, Is.Empty);

        rig.Source.AllowInsecureHttp = true;
        Assert.That((await rig.Syncer.SyncAsync(rig.Source, false, default)).Status, Is.EqualTo(SyncStatus.Ok));

        rig.Source.Name = "../etc/passwd";
        Assert.That((await rig.Syncer.SyncAsync(rig.Source, false, default)).Message, Does.Contain("Source names"));
    }

    [Test]
    public async Task ServerErrorsAreReportedAndKeepExistingEntries()
    {
        await using var rig = await CreateAsync("203.0.113.1\n");
        await rig.Syncer.SyncAsync(rig.Source, false, default);

        rig.Http.Status = HttpStatusCode.ServiceUnavailable;
        var result = await rig.Syncer.SyncAsync(rig.Source, false, default);

        Assert.That(result.Status, Is.EqualTo(SyncStatus.Error));
        Assert.That(result.Message, Does.Contain("503"));
        Assert.That(await rig.Store.GetActiveAsync(default), Has.Count.EqualTo(1));
    }

    [Test]
    public async Task CustomHeadersAreSentButNotLogged()
    {
        await using var rig = await CreateAsync("203.0.113.1\n", s => s.Headers["Authorization"] = "Bearer secret-token");
        await rig.Syncer.SyncAsync(rig.Source, false, default);
        Assert.That(rig.Http.Requests[0].Headers.Authorization?.Parameter, Is.EqualTo("secret-token"));
    }

    [Test]
    public async Task BulkAddSkipsActiveAddressesAndDuplicates()
    {
        await using var temp = new TempStore();
        var store = await temp.CreateAsync();
        await store.AddAsync(new Ban { Address = "203.0.113.1", Source = "manual", CreatedUtc = DateTime.UtcNow }, default);

        int added = await store.AddRangeAsync(
        [
            new Ban { Address = "203.0.113.1", Source = "blocklist:x" },
            new Ban { Address = "203.0.113.2", Source = "blocklist:x" },
            new Ban { Address = "203.0.113.2", Source = "blocklist:x" },
        ], default);

        Assert.That(added, Is.EqualTo(1));
        Assert.That(await store.GetActiveAsync(default), Has.Count.EqualTo(2));
    }

    [Test]
    public async Task LargeListImportsAndRefreshesQuickly()
    {
        string big = string.Join('\n', Enumerable.Range(0, 5000).Select(i => $"100.{i / 65025 % 256}.{i / 255 % 255}.{i % 255 + 1}"));
        await using var rig = await CreateAsync(big);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var result = await rig.Syncer.SyncAsync(rig.Source, false, default);
        watch.Stop();

        Assert.That(result.Added, Is.EqualTo(5000));
        Assert.That(watch.Elapsed, Is.LessThan(TimeSpan.FromSeconds(30)));
        var again = await rig.Syncer.SyncAsync(rig.Source, false, default);
        Assert.That((again.Added, again.Removed), Is.EqualTo((0, 0)));
    }
}

public class SyncCommandTests
{
    [Test]
    public async Task WithoutSourcesTheCommandExplainsWhat()
    {
        string dir = Path.Combine(Path.GetTempPath(), "banish-sync-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string config = Path.Combine(dir, "b.json");
            File.WriteAllText(config, $$"""{ "Store": { "Provider": "Sqlite", "ConnectionString": "Data Source={{Path.Combine(dir, "b.db").Replace("\\", "/")}}" }, "Rules": [] }""");
            var err = new StringWriter();
            int code = await CliApp.RunAsync(["--config", config, "sync"], new StringWriter(), err, default);

            Assert.That(code, Is.EqualTo(1));
            Assert.That(err.ToString(), Does.Contain("Sync:Sources"));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, true);
        }
    }
}
