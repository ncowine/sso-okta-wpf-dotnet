using System.Collections.Concurrent;

namespace Corp.Identity;

public interface IAccessTokenCache
{
    bool TryGet(string resource, out string token);
    void Set(string resource, string token, DateTimeOffset expiresAt);
    void Remove(string resource);
    void Clear();
    DateTimeOffset? ExpiryOf(string resource);
}

/// <summary>
/// In-memory access tokens, renewed BEFORE expiry rather than after a 401. README §8.8.
/// </summary>
/// <remarks>
/// A proactive refresh is invisible to the user; a reactive one costs them a failed
/// request. Access tokens never touch disk (README §12.3).
/// </remarks>
public sealed class AccessTokenCache : IAccessTokenCache
{
    /// <summary>
    /// Renew this far ahead of exp. Covers clock skew between the desktop and the API
    /// host, plus the round trip itself.
    /// </summary>
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(90);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    public bool TryGet(string resource, out string token)
    {
        token = string.Empty;

        if (!_entries.TryGetValue(resource, out var entry)) return false;

        if (DateTimeOffset.UtcNow >= entry.ExpiresAt - Skew)
        {
            _entries.TryRemove(resource, out _);
            return false;
        }

        token = entry.Token;
        return true;
    }

    public void Set(string resource, string token, DateTimeOffset expiresAt) =>
        _entries[resource] = new Entry(token, expiresAt);

    public void Remove(string resource) => _entries.TryRemove(resource, out _);

    public void Clear() => _entries.Clear();

    public DateTimeOffset? ExpiryOf(string resource) =>
        _entries.TryGetValue(resource, out var entry) ? entry.ExpiresAt : null;

    private readonly record struct Entry(string Token, DateTimeOffset ExpiresAt);
}
