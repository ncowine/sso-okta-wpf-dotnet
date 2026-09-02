using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Corp.Identity;

public interface ITokenStore
{
    Task SaveAsync(StoredTokens tokens, CancellationToken ct = default);
    Task<StoredTokens?> LoadAsync(CancellationToken ct = default);
    void Clear();
}

/// <summary>What we persist between runs. README §E.1.</summary>
/// <remarks>
/// Access tokens are deliberately absent: they expire in minutes and can be re-minted
/// silently, so persisting one only adds a disk-resident bearer credential.
/// The ID token is kept solely because RP-initiated logout needs it as id_token_hint.
/// </remarks>
public sealed record StoredTokens
{
    /// <summary>
    /// Refresh tokens keyed by authorization server ID. A refresh token is scoped to the
    /// server that issued it, so under Variant B (one AS per API) a client that talks to
    /// two APIs holds two of them (README §5.2, §8.9).
    /// </summary>
    public Dictionary<string, string> RefreshTokens { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Kept solely because RP-initiated logout needs it as id_token_hint (README §11.2).</summary>
    public string? IdToken { get; init; }

    public DateTimeOffset ObtainedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Refresh-token storage encrypted with DPAPI under the CurrentUser scope. README §8.6.
/// </summary>
/// <remarks>
/// <para>What this gives you: the blob is decryptable only by the same Windows user on
/// the same machine (or wherever their roaming profile reaches). That defeats another
/// user on a shared machine, a stolen laptop with the disk pulled, a file copied to a
/// share, and an over-broad backup.</para>
/// <para>What it does NOT give you: protection from malware running as the signed-in
/// user — that code can call Unprotect exactly as this class does. No in-process
/// technique on a general-purpose desktop OS changes that. The controls that actually
/// bound the damage are short access-token lifetimes, rotating refresh tokens with
/// reuse detection (README §5.6), and DPoP (README §12.4).</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class DpapiTokenStore : ITokenStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Corp.Identity.v1");

    private readonly string _path;
    private readonly bool _persist;
    private readonly ILogger<DpapiTokenStore> _log;

    public DpapiTokenStore(IOptions<OktaClientOptions> options, ILogger<DpapiTokenStore> log)
    {
        var o = options.Value;
        _log = log;
        _persist = o.PersistSession;

        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Corp",
            o.ApplicationName);
        Directory.CreateDirectory(dir);

        // Per client_id: AppA and AppB must never read each other's tokens (README §4.7).
        _path = Path.Combine(dir, $"{o.ClientId}.tokens");
    }

    public async Task SaveAsync(StoredTokens tokens, CancellationToken ct = default)
    {
        if (!_persist)
        {
            // Shared or kiosk machine: never leave a resumable session behind (README §E.7).
            return;
        }

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(tokens);
        try
        {
            var encrypted = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);

            // Write-then-move: a crash mid-write must not leave a truncated file that
            // forces a needless re-authentication on next launch.
            var tmp = _path + ".tmp";
            await File.WriteAllBytesAsync(tmp, encrypted, ct).ConfigureAwait(false);
            File.Move(tmp, _path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task<StoredTokens?> LoadAsync(CancellationToken ct = default)
    {
        if (!_persist || !File.Exists(_path)) return null;

        byte[]? plaintext = null;
        try
        {
            var encrypted = await File.ReadAllBytesAsync(_path, ct).ConfigureAwait(false);
            plaintext = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<StoredTokens>(plaintext);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or IOException)
        {
            // Roaming profile moved, machine rebuilt, or the file was tampered with.
            // Unrecoverable and not an error condition: delete and re-authenticate.
            _log.LogInformation("Token store unreadable ({Reason}); clearing and re-authenticating",
                                ex.GetType().Name);
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
            _log.LogWarning(ex, "Could not delete the token store at {Path}", _path);
        }
    }
}
