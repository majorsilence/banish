using Majorsilence.Banish.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Majorsilence.Banish.Store.Ef;

public sealed class BanishDbContext : DbContext
{
    public BanishDbContext(DbContextOptions<BanishDbContext> options)
        : base(options)
    {
    }

    public DbSet<Ban> Bans => Set<Ban>();
    public DbSet<BanEvent> BanEvents => Set<BanEvent>();
    public DbSet<AllowEntry> Allowlist => Set<AllowEntry>();
    public DbSet<AgentInfo> Agents => Set<AgentInfo>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Ban>(e =>
        {
            e.ToTable("Bans");
            e.HasKey(b => b.Id);
            e.Property(b => b.Address).HasMaxLength(64).IsRequired();
            e.Property(b => b.Reason).HasMaxLength(512);
            e.Property(b => b.Source).HasMaxLength(128).IsRequired();
            e.Property(b => b.RuleId).HasMaxLength(128);
            e.Property(b => b.RemovedBy).HasMaxLength(128);
            e.Property(b => b.MachineName).HasMaxLength(128);
            e.Property(b => b.CreatedBy).HasMaxLength(128);
            e.HasIndex(b => b.Address);
            e.HasIndex(b => b.RemovedUtc);
            e.HasIndex(b => b.CreatedUtc);
        });

        modelBuilder.Entity<BanEvent>(e =>
        {
            e.ToTable("BanEvents");
            e.HasKey(b => b.Id);
            e.Property(b => b.Address).HasMaxLength(64).IsRequired();
            e.Property(b => b.Kind).HasMaxLength(32).IsRequired();
            e.Property(b => b.Actor).HasMaxLength(128);
            e.Property(b => b.MachineName).HasMaxLength(128);
            e.Property(b => b.Detail).HasMaxLength(512);
            e.HasIndex(b => b.TimestampUtc);
        });

        modelBuilder.Entity<AllowEntry>(e =>
        {
            e.ToTable("Allowlist");
            e.HasKey(a => a.Id);
            e.Property(a => a.Address).HasMaxLength(64).IsRequired();
            e.Property(a => a.Note).HasMaxLength(256);
            e.Property(a => a.CreatedBy).HasMaxLength(128);
            e.HasIndex(a => a.Address).IsUnique();
        });

        modelBuilder.Entity<AgentInfo>(e =>
        {
            e.ToTable("Agents");
            e.HasKey(a => a.MachineName);
            e.Property(a => a.MachineName).HasMaxLength(128);
            e.Property(a => a.Os).HasMaxLength(128);
            e.Property(a => a.Version).HasMaxLength(64);
            e.Property(a => a.Firewall).HasMaxLength(64);
        });

        // All timestamps are UTC; providers differ in whether they keep the Kind.
        var utc = new ValueConverter<DateTime, DateTime>(v => v.ToUniversalTime(), v => DateTime.SpecifyKind(v, DateTimeKind.Utc));
        var utcNullable = new ValueConverter<DateTime?, DateTime?>(
            v => v.HasValue ? v.Value.ToUniversalTime() : v,
            v => v.HasValue ? DateTime.SpecifyKind(v.Value, DateTimeKind.Utc) : v);
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.ClrType == typeof(DateTime))
                {
                    property.SetValueConverter(utc);
                }
                else if (property.ClrType == typeof(DateTime?))
                {
                    property.SetValueConverter(utcNullable);
                }
            }
        }
    }
}
