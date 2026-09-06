using System.Runtime.Versioning;
using System.Security.Claims;
using Common.Authentication.Callback;
using Common.Authentication.Protocol;
using Common.Authentication.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Common.Authentication;

/// <summary>
/// The one implementation behind <see cref="IAuthenticationService"/>. Holds the session,
/// decides when to refresh, and keeps the rest of the application away from tokens.
/// </summary>
/// <remarks>
/// Read this class as four small jobs: restore a session at startup, sign in when there
/// isn't one, hand out access tokens on request, and sign out. Everything else here exists
/// to make those four safe when several parts of the UI ask at the same time.
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class AuthenticationService : IAuthenticationService, IDisposable
{
    private readonly AuthenticationOptions _options;
    private readonly OpenIdConnectClient _client;
    private readonly ITokenStore _store;
    private readonly AccessTokenCache _accessTokens;
    private readonly ILogger<AuthenticationService> _log;

    /// <summary>
    /// Lets exactly one token operation happen at a time.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is not caution for its own sake. A WPF shell routinely loads several view
    /// models at once when you navigate, and each may ask for a token. Without this gate
    /// they all reach the provider together, each presenting the same refresh token.
    /// </para>
    /// <para>
    /// Where the provider rotates refresh tokens — and it should — the first call
    /// invalidates the token the others are still holding. The provider sees the rest as
    /// replay, which is exactly what a stolen token looks like, and can revoke the whole
    /// family. The user is signed out for no reason, intermittently, under load. It is a
    /// miserable bug to reproduce and a one-line fix to prevent.
    /// </para>
    /// </remarks>
    private readonly SemaphoreSlim _gate = new(1, 1);

    private StoredSession _session = new();
    private bool _disposed;

    public AuthenticationService(
        IOptions<AuthenticationOptions> options,
        OpenIdConnectClient client,
        ITokenStore store,
        AccessTokenCache accessTokens,
        ILogger<AuthenticationService> log)
    {
        _options = options.Value;
        _client = client;
        _store = store;
        _accessTokens = accessTokens;
        _log = log;
    }

    public bool IsSignedIn => User?.Identity?.IsAuthenticated == true;

    public ClaimsPrincipal? User { get; private set; }

    public event EventHandler<AuthenticationStateChangedEventArgs>? StateChanged;

    // ── Getting signed in ────────────────────────────────────────────────────

    public async Task<AuthenticationResult> RestoreSessionAsync(CancellationToken cancellationToken = default)
    {
        _session = await _store.LoadAsync(cancellationToken).ConfigureAwait(false) ?? new StoredSession();

        if (string.IsNullOrEmpty(_session.RefreshToken)) return AuthenticationResult.NoStoredSession();

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var tokens = await _client.RefreshAsync(_session.RefreshToken, cancellationToken)
                .ConfigureAwait(false);

            await AcceptTokensAsync(tokens, cancellationToken).ConfigureAwait(false);

            Announce(AuthenticationChangeReason.SessionRestored);
            _log.LogInformation("Restored the previous session");

            return AuthenticationResult.Success(User!);
        }
        catch (AuthenticationException ex)
        {
            // Routine, not exceptional: the token expired, was rotated out, or an admin
            // revoked it. All of them mean the same thing — ask the user.
            _log.LogInformation("Could not restore the session ({Reason}); a sign-in is needed", ex.Error);

            ForgetSession();
            return AuthenticationResult.NoStoredSession();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AuthenticationResult> SignInAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var scopes = ScopesFor(resource: null);

            TokenSet tokens;
            try
            {
                // Try silently first. If the browser already has a session with the
                // provider, the user sees nothing at all.
                tokens = await _client.SignInAsync(scopes, interactive: false, cancellationToken)
                    .ConfigureAwait(false);

                _log.LogInformation("Signed in without prompting, using the existing browser session");
            }
            catch (AuthenticationException silent) when (silent.NeedsUserInteraction)
            {
                _log.LogInformation("The provider asked for a sign-in ({Reason}); opening the browser", silent.Error);

                tokens = await _client.SignInAsync(scopes, interactive: true, cancellationToken)
                    .ConfigureAwait(false);
            }

            await AcceptTokensAsync(tokens, cancellationToken).ConfigureAwait(false);

            Announce(AuthenticationChangeReason.SignedIn);
            _log.LogInformation("Signed in as {Subject}", SubjectOf(User));

            return AuthenticationResult.Success(User!);
        }
        catch (OperationCanceledException)
        {
            return AuthenticationResult.Cancelled();
        }
        catch (AuthenticationException ex)
        {
            _log.LogWarning("Sign-in failed: {Reason}", ex.Error);
            return AuthenticationResult.Failed(ex.Error, ex.ErrorDescription);
        }
        finally
        {
            _gate.Release();
        }
    }

    // ── Handing out tokens ───────────────────────────────────────────────────

    public async Task<string> GetAccessTokenAsync(
        string resourceName, CancellationToken cancellationToken = default)
    {
        // The common case, and it never waits on the gate.
        if (_accessTokens.TryGet(resourceName, out var cached)) return cached;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Look again. Someone else may have refreshed while we queued, in which case
            // there is nothing left to do.
            if (_accessTokens.TryGet(resourceName, out cached)) return cached;

            if (!_options.Resources.ContainsKey(resourceName))
            {
                throw new AuthenticationException(
                    "unknown_resource",
                    $"'{resourceName}' is not configured. Add it under " +
                    $"{AuthenticationOptions.SectionName}:Resources.");
            }

            if (string.IsNullOrEmpty(_session.RefreshToken))
            {
                throw new AuthenticationException(
                    "not_signed_in", "There is no session. Sign in before calling this API.");
            }

            TokenSet tokens;
            try
            {
                tokens = await _client.RefreshAsync(_session.RefreshToken, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (AuthenticationException)
            {
                // The refresh token is gone for good — expired, rotated out, or revoked.
                // Drop the session and say so, because the UI needs to tell the difference
                // between "your session ended, sign in again" and "something broke".
                ForgetSession();
                Announce(AuthenticationChangeReason.SessionExpired);
                throw;
            }

            await AcceptTokensAsync(tokens, cancellationToken).ConfigureAwait(false);
            Announce(AuthenticationChangeReason.TokenRefreshed);

            // The refresh gives one access token; cache it under the resource that asked.
            _accessTokens.Set(resourceName, tokens.AccessToken, tokens.ExpiresAt);
            return tokens.AccessToken;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void InvalidateAccessToken(string resourceName) => _accessTokens.Remove(resourceName);

    public bool HasScope(string scope) =>
        User?.FindAll("scp").Any(claim =>
            claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                 .Contains(scope, StringComparer.Ordinal)) == true;

    // ── Signing out ──────────────────────────────────────────────────────────

    public async Task SignOutAsync(SignOutScope scope, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        string? identityToken;
        string? refreshToken;

        try
        {
            identityToken = _session.IdentityToken;
            refreshToken = _session.RefreshToken;

            // Revoke at the provider FIRST. If this process dies straight afterwards, a
            // still-valid refresh token left alive at the provider is worse than a local
            // file we failed to delete.
            if (!string.IsNullOrEmpty(refreshToken))
            {
                await _client.RevokeRefreshTokenAsync(refreshToken, cancellationToken).ConfigureAwait(false);
            }

            ForgetSession();
        }
        finally
        {
            _gate.Release();
        }

        Announce(AuthenticationChangeReason.SignedOut);

        if (scope == SignOutScope.Everywhere && !string.IsNullOrEmpty(identityToken))
        {
            await _client.SignOutOfProviderAsync(identityToken, cancellationToken).ConfigureAwait(false);
        }
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// <summary>
    /// Takes the result of a successful call: persists the rotated refresh token, caches
    /// the access token, and updates who is signed in.
    /// </summary>
    /// <remarks>
    /// The refresh token is written before anything else can fail. Where the provider
    /// rotates them, the previous one is already dead the moment this response arrived —
    /// so if we crash before the write, the user faces an unexplained sign-in next launch.
    /// </remarks>
    private async Task AcceptTokensAsync(TokenSet tokens, CancellationToken cancellationToken)
    {
        _session = _session with
        {
            RefreshToken = tokens.RefreshToken ?? _session.RefreshToken,
            IdentityToken = tokens.IdentityToken ?? _session.IdentityToken,
            StoredAt = DateTimeOffset.UtcNow,
        };

        await _store.SaveAsync(_session, cancellationToken).ConfigureAwait(false);

        User = tokens.User
               ?? User
               ?? (_session.IdentityToken is null
                   ? null
                   : IdentityTokenValidator.ReadStoredToken(_session.IdentityToken));
    }

    /// <summary>Drops every trace of the current session, on disk and in memory.</summary>
    private void ForgetSession()
    {
        _store.Clear();
        _accessTokens.Clear(_options.Resources.Keys);
        _session = new StoredSession();
        User = null;
    }

    /// <summary>The shared scopes, plus one resource's own if named.</summary>
    private string[] ScopesFor(string? resource)
    {
        var scopes = _options.Scopes.AsEnumerable();

        if (resource is not null && _options.Resources.TryGetValue(resource, out var options))
        {
            scopes = scopes.Concat(options.Scopes);
        }
        else
        {
            // No resource named: ask for everything this application will ever need, so
            // one round trip covers the whole session.
            scopes = scopes.Concat(_options.Resources.Values.SelectMany(r => r.Scopes));
        }

        return scopes.Distinct(StringComparer.Ordinal).ToArray();
    }

    private void Announce(AuthenticationChangeReason reason) =>
        StateChanged?.Invoke(this, new AuthenticationStateChangedEventArgs(reason, User));

    private static string SubjectOf(ClaimsPrincipal? user) =>
        user?.FindFirst("sub")?.Value ?? "unknown";

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _gate.Dispose();
    }
}
