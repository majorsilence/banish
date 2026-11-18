using Majorsilence.Banish.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Majorsilence.Banish.Store.Ef;

/// <summary>Local dashboard accounts: PBKDF2-hashed passwords with lockout after repeated failures.</summary>
public sealed class UserService
{
    public const int MinPasswordLength = 12;
    public const int MaxFailedLogins = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private static readonly PasswordHasher<AdminUser> Hasher = new();
    private readonly IDbContextFactory<BanishDbContext> _factory;
    private readonly TimeProvider _time;

    public UserService(IDbContextFactory<BanishDbContext> factory, TimeProvider? time = null)
    {
        _factory = factory;
        _time = time ?? TimeProvider.System;
    }

    private DateTime Now => _time.GetUtcNow().UtcDateTime;

    public async Task<AdminUser> CreateAsync(string userName, string password, string role, CancellationToken ct)
    {
        userName = userName.Trim();
        if (userName.Length is < 1 or > 128)
        {
            throw new ArgumentException("A user name of 1-128 characters is required.");
        }

        if (role is not (ApiRoles.Admin or ApiRoles.Viewer))
        {
            throw new ArgumentException($"Role must be '{ApiRoles.Admin}' or '{ApiRoles.Viewer}'.");
        }

        CheckPassword(password);
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        if (await db.Users.AnyAsync(u => u.UserName == userName, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"User '{userName}' already exists.");
        }

        var user = new AdminUser { UserName = userName, Role = role, CreatedUtc = Now };
        user.PasswordHash = Hasher.HashPassword(user, password);
        db.Users.Add(user);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return user;
    }

    /// <summary>Returns the user when the password is right and the account is not locked; otherwise null.</summary>
    public async Task<AdminUser?> ValidateAsync(string userName, string password, CancellationToken ct)
    {
        userName = userName.Trim();
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var user = await db.Users.FirstOrDefaultAsync(u => u.UserName == userName, ct).ConfigureAwait(false);
        if (user is null)
        {
            // Spend the same time as a real check so existence of an account is not observable.
            Hasher.VerifyHashedPassword(new AdminUser(), DummyHash, password);
            return null;
        }

        var now = Now;
        if (user.LockoutUntilUtc > now)
        {
            return null;
        }

        var result = Hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (result == PasswordVerificationResult.Failed)
        {
            user.FailedLogins++;
            if (user.FailedLogins >= MaxFailedLogins)
            {
                user.LockoutUntilUtc = now + LockoutDuration;
                user.FailedLogins = 0;
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return null;
        }

        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = Hasher.HashPassword(user, password);
        }

        user.FailedLogins = 0;
        user.LockoutUntilUtc = null;
        user.LastLoginUtc = now;
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return user;
    }

    public async Task<IReadOnlyList<AdminUser>> ListAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await db.Users.AsNoTracking().OrderBy(u => u.UserName).ToListAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> DeleteAsync(string userName, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var user = await db.Users.FirstOrDefaultAsync(u => u.UserName == userName, ct).ConfigureAwait(false);
        if (user is null)
        {
            return false;
        }

        db.Users.Remove(user);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }

    public async Task<bool> SetPasswordAsync(string userName, string password, CancellationToken ct)
    {
        CheckPassword(password);
        await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var user = await db.Users.FirstOrDefaultAsync(u => u.UserName == userName, ct).ConfigureAwait(false);
        if (user is null)
        {
            return false;
        }

        user.PasswordHash = Hasher.HashPassword(user, password);
        user.FailedLogins = 0;
        user.LockoutUntilUtc = null;
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }

    private static readonly string DummyHash = Hasher.HashPassword(new AdminUser(), "not-a-real-password-0000");

    private static void CheckPassword(string password)
    {
        if (password is null || password.Length < MinPasswordLength)
        {
            throw new ArgumentException($"Passwords need at least {MinPasswordLength} characters.");
        }
    }
}
