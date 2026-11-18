namespace Majorsilence.Banish.Core;

/// <summary>Holds the current allow-list: configuration entries plus those kept in the shared store.</summary>
public sealed class AllowlistProvider
{
    private readonly Allowlist _configured;
    private volatile Allowlist _current;

    public AllowlistProvider(AllowlistOptions options)
    {
        _configured = Allowlist.Create(options.Entries, options.IncludePrivateRanges);
        _current = _configured;
    }

    public Allowlist Current => _current;

    public async Task RefreshAsync(IBanStore store, CancellationToken cancellationToken)
    {
        var entries = await store.GetAllowlistAsync(cancellationToken).ConfigureAwait(false);
        _current = _configured.With(entries.Select(e => e.Address));
    }
}
