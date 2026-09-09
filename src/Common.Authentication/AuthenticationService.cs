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
    private readonly OpenIdConnectClientFactory _clients;
    private readonly ITokenStore _store;
    private readonly AccessTokenCache _accessTokens;
    private readonly ILogger<AuthenticationService> _log;

    /// <summary>The client for the server the user signs in against. Everything except a
    /// resource with its own configured <c>Authority</c> goes through this one.</summary>
    private OpenIdConnectClient PrimaryClient => _clients.Primary;

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
        OpenIdConnectClientFactory clients,
        ITokenStore store,
        AccessTokenCache accessTokens,
        ILogger<AuthenticationService> log)
    {
        _options = options.Value;
        _clients = clients;
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
            var tokens = await PrimaryClient.RefreshAsync(_session.RefreshToken, cancellationToken)
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
                tokens = await PrimaryClient.SignInAsync(scopes, interactive: false, cancellationToken)
                    .ConfigureAwait(false);

                _log.LogInformation("Signed in without prompting, using the existing browser session");
            }
            catch (AuthenticationException silent) when (silent.NeedsUserInteraction)
            {
                _log.LogInformation("The provider asked for a sign-in ({Reason}); opening the browser", silent.Error);

                tokens = await PrimaryClient.SignInAsync(scopes, interactive: true, cancellationToken)
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

            if (!_options.Resources.TryGetValue(resourceName, out var resource))
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

            // A resource with its own Authority is served by a different authorization
            // server; it gets its own token, and never touches the primary session.
            var (accessToken, expiresAt) = resource.HasOwnAuthority(_options.Authority)
                ? await TokenFromResourceAuthorityAsync(resource, cancellationToken).ConfigureAwait(false)
                : await TokenFromPrimaryAsync(cancellationToken).ConfigureAwait(false);

            _accessTokens.Set(resourceName, accessToken, expiresAt);
            return accessToken;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The default path: one refresh against the sign-in server yields one token.</summary>
    private async Task<(string AccessToken, DateTimeOffset ExpiresAt)> TokenFromPrimaryAsync(
        CancellationToken cancellationToken)
    {
        TokenSet tokens;
        try
        {
            tokens = await PrimaryClient.RefreshAsync(_session.RefreshToken!, cancellationToken)
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

        return (tokens.AccessToken, tokens.ExpiresAt);
    }

    /// <summary>
    /// Gets a token for a resource whose authorization server is not the one we signed in
    /// against — an application calling two APIs directly, each with its own server.
    /// </summary>
    /// <remarks>
    /// Uses a refresh token of its own if one is held; otherwise a silent <c>prompt=none</c>
    /// authorize, which the browser session from the primary sign-in lets through without a
    /// prompt. A failure here is that resource's problem alone — the primary session, and
    /// every other resource, is untouched.
    /// </remarks>
    private async Task<(string AccessToken, DateTimeOffset ExpiresAt)> TokenFromResourceAuthorityAsync(
        ResourceOptions resource, CancellationToken cancellationToken)
    {
        var client = _clients.ForAuthority(resource.Authority!);

        if (_session.ResourceRefreshTokens.TryGetValue(client.Authority, out var stored))
        {
            try
            {
                var refreshed = await client.RefreshAsync(stored, cancellationToken).ConfigureAwait(false);
                await RememberResourceRefreshTokenAsync(
                    client.Authority, refreshed.RefreshToken ?? stored, cancellationToken).ConfigureAwait(false);
                return (refreshed.AccessToken, refreshed.ExpiresAt);
            }
            catch (AuthenticationException ex)
            {
                _log.LogInformation(
                    "The stored token for {Authority} could not be refreshed ({Reason}); re-authorizing silently",
                    client.Authority, ex.Error);

                await ForgetResourceRefreshTokenAsync(client.Authority, cancellationToken).ConfigureAwait(false);
            }
        }

        var scopes = ResourceAuthorityScopes(resource);

        TokenSet tokens;
        try
        {
            tokens = await client.SignInAsync(scopes, interactive: false, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (AuthenticationException silent) when (silent.NeedsUserInteraction)
        {
            _log.LogInformation(
                "{Authority} asked for interaction ({Reason}); opening the browser",
                client.Authority, silent.Error);

            tokens = await client.SignInAsync(scopes, interactive: true, cancellationToken)
                .ConfigureAwait(false);
        }

        if (!string.IsNullOrEmpty(tokens.RefreshToken))
        {
            await RememberResourceRefreshTokenAsync(client.Authority, tokens.RefreshToken, cancellationToken)
                .ConfigureAwait(false);
        }

        _log.LogInformation("Obtained a token for {Authority} directly", client.Authority);
        return (tokens.AccessToken, tokens.ExpiresAt);
    }

    /// <summary>
    /// Scopes for a direct call to a resource's own server: <c>openid</c> so an ID token
    /// comes back (the protocol client needs one), <c>offline_access</c> for a refresh token
    /// so we do not re-authorize on every call, then the resource's own scopes.
    /// <c>profile</c> and <c>email</c> are the primary server's concern, not this one's.
    /// </summary>
    private static string[] ResourceAuthorityScopes(ResourceOptions resource) =>
        new[] { "openid", "offline_access" }
            .Concat(resource.Scopes)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private async Task RememberResourceRefreshTokenAsync(
        string authority, string refreshToken, CancellationToken cancellationToken)
    {
        _session.ResourceRefreshTokens[authority] = refreshToken;
        await _store.SaveAsync(_session, cancellationToken).ConfigureAwait(false);
    }

    private async Task ForgetResourceRefreshTokenAsync(string authority, CancellationToken cancellationToken)
    {
        if (_session.ResourceRefreshTokens.Remove(authority))
            await _store.SaveAsync(_session, cancellationToken).ConfigureAwait(false);
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
                await PrimaryClient.RevokeRefreshTokenAsync(refreshToken, cancellationToken).ConfigureAwait(false);
            }

            // And any token held for a resource's own authorization server, each against
            // the server that issued it. Best-effort, exactly like the primary one.
            foreach (var (authority, token) in _session.ResourceRefreshTokens)
            {
                await _clients.ForAuthority(authority)
                    .RevokeRefreshTokenAsync(token, cancellationToken).ConfigureAwait(false);
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
            await PrimaryClient.SignOutOfProviderAsync(identityToken, cancellationToken).ConfigureAwait(false);
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
