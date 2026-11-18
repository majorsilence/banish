using Majorsilence.Banish.Core;
using Majorsilence.Banish.Store.Ef;
using Microsoft.EntityFrameworkCore;

namespace Majorsilence.Banish.Tests.Support;

public sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>A throw-away SQLite database in a temp file.</summary>
public sealed class TempStore : IAsyncDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"banish-test-{Guid.NewGuid():N}.db");

    public TempStore(TimeProvider? time = null, string machine = "test-host")
    {
        var options = new DbContextOptionsBuilder<BanishDbContext>().UseSqlite($"Data Source={_path}").Options;
        Factory = new OptionsFactory(options);
        Store = new EfBanStore(Factory, machine, time);
    }

    public EfBanStore Store { get; }

    public IDbContextFactory<BanishDbContext> Factory { get; }

    public string ConnectionString => $"Data Source={_path}";

    public async Task<EfBanStore> CreateAsync()
    {
        await Store.EnsureCreatedAsync(CancellationToken.None);
        return Store;
    }

    public ValueTask DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            File.Delete(_path);
        }
        catch (IOException)
        {
        }

        return ValueTask.CompletedTask;
    }

    private sealed class OptionsFactory(DbContextOptions<BanishDbContext> options) : IDbContextFactory<BanishDbContext>
    {
        public BanishDbContext CreateDbContext() => new(options);
    }
}
