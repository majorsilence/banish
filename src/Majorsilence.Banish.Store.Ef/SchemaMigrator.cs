using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Internal;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;

namespace Majorsilence.Banish.Store.Ef;

/// <summary>
/// Brings the database schema up to date with EF Core migrations (one migrations assembly per provider).
/// Databases created by version 0.1.x with <c>EnsureCreated</c> have the tables but no migration history;
/// they are recognised and recorded as already being at the first migration, so nothing is recreated.
/// </summary>
public static class SchemaMigrator
{
    public static async Task MigrateAsync(BanishDbContext db, CancellationToken cancellationToken)
    {
        var migrations = db.GetService<IMigrationsAssembly>().Migrations.Keys.Order(StringComparer.Ordinal).ToList();
        if (migrations.Count == 0)
        {
            throw new InvalidOperationException(
                "No schema migrations were found for this database provider. The migrations assembly is missing from the application folder.");
        }

        var applied = (await db.Database.GetAppliedMigrationsAsync(cancellationToken).ConfigureAwait(false)).ToList();
        if (applied.Count == 0 && await HasLegacyTablesAsync(db, cancellationToken).ConfigureAwait(false))
        {
            var history = db.GetService<IHistoryRepository>();
            var row = new HistoryRow(migrations[0], ProductInfo.GetVersion());
            await db.Database.ExecuteSqlRawAsync(history.GetCreateIfNotExistsScript(), cancellationToken).ConfigureAwait(false);
            await db.Database.ExecuteSqlRawAsync(history.GetInsertScript(row), cancellationToken).ConfigureAwait(false);
        }

        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> HasLegacyTablesAsync(BanishDbContext db, CancellationToken cancellationToken)
    {
        var creator = db.GetService<IRelationalDatabaseCreator>();
        if (!await creator.ExistsAsync(cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        try
        {
            await db.Bans.AsNoTracking().Select(b => b.Id).Take(1).ToListAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is System.Data.Common.DbException or InvalidOperationException)
        {
            return false;
        }
    }
}
