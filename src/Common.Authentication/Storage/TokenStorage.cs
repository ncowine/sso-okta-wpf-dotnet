using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Common.Authentication.Storage;

/// <summary>What we keep between runs so the user is not asked to sign in every morning.</summary>
/// <remarks>
/// Access tokens are deliberately absent. They live minutes and can be re-minted silently,
/// so writing one to disk adds a credential at rest and buys nothing. The ID token is kept
/// only because signing out properly requires presenting it back to the provider.
/// </remarks>
internal sealed record StoredSession
{
    /// <summary>The refresh token from the primary authorization server — the one sign-in used.</summary>
    public string? RefreshToken { get; init; }

    public string? IdentityToken { get; init; }
    public DateTimeOffset StoredAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Refresh tokens for resources served by a different authorization server, keyed by
    /// that server's authority. Empty for the common single-server case.
    /// </summary>
    public Dictionary<string, string> ResourceRefreshTokens { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
}

internal interface ITokenStore
{
    Task SaveAsync(StoredSession session, CancellationToken cancellationToken = default);
    Task<StoredSession?> LoadAsync(CancellationToken cancellationToken = default);
    void Clear();
}

/// <summary>
/// Keeps the refresh token on disk, encrypted with Windows DPAPI under the current user.
/// </summary>
/// <remarks>
/// <para><b>What this protects against:</b> another user on a shared machine; a stolen
/// laptop with the disk pulled out; the file copied to a share or swept into a backup.</para>
/// <para><b>What it does not:</b> malware running as the signed-in user, which can call
/// Unprotect exactly as this code does. No technique that runs in-process on a desktop OS
/// changes that. What actually limits the damage is short token lifetimes, refresh token
/// rotation, and the provider's own ability to revoke.</para>
/// <para>
/// Worth being honest about, because overstating it leads people to skip the controls that
/// do the real work.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class DpapiTokenStore : ITokenStore
{
    /// <summary>
    /// Extra entropy mixed into the encryption. Not a secret — it is in the binary — but
    /// it stops a blob written by this library being decrypted by unrelated code that
    /// happens to call DPAPI for the same user.
    /// </summary>
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Common.Authentication.v1");

    private readonly string _path;
    private readonly bool _persist;
    private readonly ILogger _log;

    public DpapiTokenStore(AuthenticationOptions options, ILogger log)
    {
        _log = log;
        _persist = options.PersistSession;

        var applicationName = options.ApplicationName ?? "Application";

        var directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            applicationName,
            "Authentication");

        Directory.CreateDirectory(directory);

        // Keyed by client id, so two applications on one desktop can never read each
        // other's session even if they share a vendor folder.
        _path = Path.Combine(directory, $"{options.ClientId}.session");
    }

    public async Task SaveAsync(StoredSession session, CancellationToken cancellationToken = default)
    {
        // Kiosk or shared machine: never leave a resumable session behind.
        if (!_persist) return;

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(session);

        try
        {
            var encrypted = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);

            // Write to a temporary file and move it into place, so a crash halfway through
            // cannot leave a half-written file that forces a needless sign-in next launch.
            var temporary = _path + ".tmp";
            await File.WriteAllBytesAsync(temporary, encrypted, cancellationToken).ConfigureAwait(false);
            File.Move(temporary, _path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task<StoredSession?> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!_persist || !File.Exists(_path)) return null;

        byte[]? plaintext = null;

        try
        {
            var encrypted = await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
            plaintext = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);

            return JsonSerializer.Deserialize<StoredSession>(plaintext);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or IOException)
        {
            // The roaming profile moved, the machine was rebuilt, or the file was touched.
            // Unrecoverable but entirely routine: throw it away and ask the user again.
            _log.LogInformation(
                "The stored session could not be read ({Reason}); signing in again", ex.GetType().Name);

            Clear();
            return null;
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public void Clear()
    {
        try
        {
            if (File.Exists(_path)) File.Delete(_path);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not delete the stored session");
        }
    }
}

/// <summary>
/// Access tokens, in memory only, renewed slightly before they expire rather than after
/// they fail.
/// </summary>
/// <remarks>
/// <para>
/// A thin policy layer over <see cref="MemoryCache"/> — Microsoft's implementation does the
/// expiry and the thread safety; what is ours is the ninety-second margin and the key
/// naming.
/// </para>
/// <para>
/// Renewing early is invisible to the user. Renewing after a 401 costs them a failed
/// request and, if you are unlucky, a visible error. The margin covers the round trip plus
/// any small clock difference with the API.
/// </para>
/// <para>
/// The cache is private to this library rather than the host's shared
/// <c>IMemoryCache</c>. Sharing would mean our entries competing with the application's
/// under its size limits — and an application that sets one would make every
/// <c>Set</c> here throw.
/// </para>
/// </remarks>
internal sealed class AccessTokenCache : IDisposable
{
    private static readonly TimeSpan RenewEarly = TimeSpan.FromSeconds(90);

    private readonly MemoryCache _cache = new(new MemoryCacheOptions());

    public bool TryGet(string resourceName, out string token) =>
        _cache.TryGetValue(Key(resourceName), out token!) && token is not null;

    public void Set(string resourceName, string token, DateTimeOffset expiresAt)
    {
        var usableUntil = expiresAt - RenewEarly;

        // Already inside the margin. Caching it would hand out a token that is about to be
        // refused, so simply do not.
        if (usableUntil <= DateTimeOffset.UtcNow) return;

        _cache.Set(Key(resourceName), token, usableUntil);
    }

    public void Remove(string resourceName) => _cache.Remove(Key(resourceName));

    /// <summary>
    /// Forgets every token. Called on sign-out.
    /// </summary>
    /// <remarks>
    /// <see cref="MemoryCache"/> has no Clear, so the caller passes the resource names it
    /// knows about. Explicit, and there is nowhere for a stray entry to hide.
    /// </remarks>
    public void Clear(IEnumerable<string> resourceNames)
    {
        foreach (var name in resourceNames) Remove(name);
    }

    private static string Key(string resourceName) => "access_token:" + resourceName;

    public void Dispose() => _cache.Dispose();
}
