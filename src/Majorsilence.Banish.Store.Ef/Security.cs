using System.Security.Cryptography;
using Majorsilence.Banish.Core;
using Microsoft.EntityFrameworkCore;

namespace Majorsilence.Banish.Store.Ef;

/// <summary>An API key (only its hash is stored).</summary>
public sealed class ApiKeyEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Unique, human-readable; for agent keys this is the machine name the key speaks for.</summary>
    public string Name { get; set; } = "";

    /// <summary>First characters of the key, to recognize it in listings.</summary>
    public string Prefix { get; set; } = "";

    public string KeyHash { get; set; } = "";
    public string Role { get; set; } = ApiRoles.Agent;
    public DateTime CreatedUtc { get; set; }
    public DateTime? LastUsedUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
}

/// <summary>A local dashboard account.</summary>
public sealed class AdminUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = ApiRoles.Admin;
    public DateTime CreatedUtc { get; set; }
    public DateTime? LastLoginUtc { get; set; }
    public int FailedLogins { get; set; }
    public DateTime? LockoutUntilUtc { get; set; }
}

/// <summary>Creates, checks and revokes API keys.</summary>
public sealed class ApiKeyService
{
    public const string KeyPrefix = "bnk_";
    private readonly IDbContextFactory<BanishDbContext> _factory;
    private readonly TimeProvider _time;

    public ApiKeyService(IDbContextFactory<BanishDbContext> factory, TimeProvider? time = null)
    {
        _factory = factory;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Creates a key; the plain text is returned once and never stored.</summary>
    public async Task<(ApiKeyEntry Entry, string Key)> CreateAsync(string name, string role, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128)
        {
            throw new ArgumentException("A key needs a name of 1-128 characters.");
        }

        if (role is not (ApiRoles.Agent or ApiRoles.Admin))
        {
            throw new ArgumentException($"Role must be '{ApiRoles.Agent}' or '{ApiRoles.Admin}'.");
        }

        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        if (await db.ApiKeys.AnyAsync(k => k.Name == name && k.RevokedUtc == null, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"An active key named '{name}' already exists.");
        }

        string key = KeyPrefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var entry = new ApiKeyEntry
        {
            Name = name,
            Role = role,
            Prefix = key[..8],
            KeyHash = Hash(key),
            CreatedUtc = _time.GetUtcNow().UtcDateTime,
        };
        db.ApiKeys.Add(entry);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return (entry, key);
    }

    /// <summary>Returns the key's entry if the key is valid and not revoked.</summary>
    public async Task<ApiKeyEntry?> ValidateAsync(string? key, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(key) || !key.StartsWith(KeyPrefix, StringComparison.Ordinal) || key.Length > 128)
        {
            return null;
        }

        string hash = Hash(key);
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var entry = await db.ApiKeys.FirstOrDefaultAsync(k => k.KeyHash == hash && k.RevokedUtc == null, ct).ConfigureAwait(false);
        if (entry is null)
        {
            return null;
        }

        var now = _time.GetUtcNow().UtcDateTime;
        if (entry.LastUsedUtc is null || now - entry.LastUsedUtc > TimeSpan.FromMinutes(1))
        {
            entry.LastUsedUtc = now;
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        return entry;
    }

    public async Task<IReadOnlyList<ApiKeyEntry>> ListAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await db.ApiKeys.AsNoTracking().OrderBy(k => k.Name).ThenBy(k => k.CreatedUtc).ToListAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> RevokeAsync(string name, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var entry = await db.ApiKeys.FirstOrDefaultAsync(k => k.Name == name && k.RevokedUtc == null, ct).ConfigureAwait(false);
        if (entry is null)
        {
            return false;
        }

        entry.RevokedUtc = _time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }

    public static string Hash(string key) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(key)));
}
