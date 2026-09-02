using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Claims;
using Corp.Identity.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Corp.Identity;

/// <summary>
/// Authorization Code + PKCE against Okta Custom Authorization Servers, via the system
/// browser and a loopback redirect. README §8.7, §8.8, §8.9.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OktaAuthenticationService : IAuthenticationService
{
    private readonly OktaClientOptions _options;
    private readonly ITokenStore _store;
    private readonly IAccessTokenCache _accessTokens;
    private readonly ILogger<OktaAuthenticationService> _log;
    private readonly ILoggerFactory _loggerFactory;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly Func<Action?> _focusRestorer;

    /// <summary>
    /// Serialises token acquisition. NOT optional: a shell routinely fires several view
    /// models' loads on navigation. Without this they race into simultaneous refresh calls
    /// with the SAME rotating refresh token — and with rotation enabled the second presents
    /// an already-rotated token, which Okta reads as replay and can invalidate the whole
    /// family, signing the user out for no reason. README §8.7.
    /// </summary>
    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly Dictionary<string, OpenIdConnectClient> _clients = new(StringComparer.Ordinal);
    private StoredTokens _tokens = new();

    public OktaAuthenticationService(
        IOptions<OktaClientOptions> options,
        ITokenStore store,
        IAccessTokenCache accessTokens,
        ILoggerFactory loggerFactory,
        IHttpClientFactory httpClientFactory,
        Func<Action?>? focusRestorer = null)
    {
        _options = options.Value;
        _store = store;
        _accessTokens = accessTokens;
        _loggerFactory = loggerFactory;
        _log = loggerFactory.CreateLogger<OktaAuthenticationService>();
        _httpClientFactory = httpClientFactory;
        _focusRestorer = focusRestorer ?? (() => null);

        _options.Validate();
    }

    public bool IsAuthenticated => User?.Identity?.IsAuthenticated == true;

    public ClaimsPrincipal? User { get; private set; }

    public event EventHandler<AuthenticationStateChangedEventArgs>? StateChanged;

    // ── Sign-in ──────────────────────────────────────────────────────────────

    public async Task<AuthenticationResult> SignInAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var result = await AuthorizeAsync(_options.PrimaryResource, allowInteractive: true, ct)
                .ConfigureAwait(false);

            if (!result.Succeeded) return result;

            Raise(AuthenticationChangeReason.SignedIn);
            _log.LogInformation("Signed in as {Subject}", SubjectOf(User));
            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AuthenticationResult> TryRestoreSessionAsync(CancellationToken ct = default)
    {
        _tokens = await _store.LoadAsync(ct).ConfigureAwait(false) ?? new StoredTokens();

        var resource = _options.PrimaryResource;
        if (!_tokens.RefreshTokens.ContainsKey(resource.AuthorizationServerId))
            return AuthenticationResult.NoSession();

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RefreshAsync(resource, ct).ConfigureAwait(false);
            Raise(AuthenticationChangeReason.SessionRestored);

            return User is not null
                ? AuthenticationResult.Success(User)
                : AuthenticationResult.NoSession();
        }
        catch (RefreshFailedException ex)
        {
            // Expected and routine: the refresh token expired, was rotated out, was
            // revoked by an admin, or the user was deprovisioned. Not an error — it just
            // means an interactive sign-in is required.
            _log.LogInformation("Session could not be restored ({Reason}); sign-in required", ex.OktaError);
            _store.Clear();
            _tokens = new StoredTokens();
            return AuthenticationResult.NoSession();
        }
        finally
        {
            _gate.Release();
        }
    }

    // ── Token acquisition ────────────────────────────────────────────────────

    public async Task<string> GetAccessTokenAsync(string resourceName, CancellationToken ct = default)
    {
        if (_accessTokens.TryGet(resourceName, out var cached)) return cached;

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Re-check: a concurrent caller may have refreshed while we waited.
            if (_accessTokens.TryGet(resourceName, out cached)) return cached;

            if (!_options.Resources.TryGetValue(resourceName, out var resource))
            {
                throw new InvalidOperationException(
                    $"Unknown resource '{resourceName}'. Add it under Okta:Resources in appsettings.json.");
            }

            // A refresh token is scoped to the authorization server that issued it. Under
            // Variant B (one AS per API) a token from apia-as is useless at apib-as, so a
            // second audience needs its own authorize round trip — silent, because the
            // Okta session cookie is already in the browser (README §5.2, §8.9).
            if (_tokens.RefreshTokens.ContainsKey(resource.AuthorizationServerId))
                return await RefreshAsync(resource, ct).ConfigureAwait(false);

            _log.LogInformation(
                "No refresh token for authorization server {AuthServer}; acquiring a token for " +
                "{Resource} via a silent authorize (README §8.9)",
                resource.AuthorizationServerId, resource.Name);

            var result = await AuthorizeAsync(resource, allowInteractive: true, ct).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new RefreshFailedException(result.Error ?? "authorize_failed", result.ErrorDescription);

            return _accessTokens.TryGet(resourceName, out var acquired)
                ? acquired
                : throw new RefreshFailedException("no_access_token");
        }
        finally
        {
            _gate.Release();
        }
    }

    public void InvalidateAccessToken(string resourceName) => _accessTokens.Remove(resourceName);

    /// <summary>
    /// Tries <c>prompt=none</c> first and only shows a window if the authorization server
    /// says one is needed. A silent success is what makes launching the second application
    /// of the day prompt-free (README §8.9, §10.1).
    /// </summary>
    private async Task<AuthenticationResult> AuthorizeAsync(
        ResourceOptions resource, bool allowInteractive, CancellationToken ct)
    {
        var client = ClientFor(resource);
        var scopes = _options.Scopes.Concat(resource.Scopes).Distinct(StringComparer.Ordinal).ToArray();

        TokenSet tokens;
        try
        {
            tokens = await client.AuthorizeAsync(scopes, interactive: false, ct).ConfigureAwait(false);
        }
        catch (AuthorizeException ex) when (ex.IsInteractionRequired)
        {
            if (!allowInteractive) return AuthenticationResult.Failed(ex.Error, ex.ErrorDescription);

            _log.LogInformation("Silent authorize returned {Error}; prompting interactively", ex.Error);

            try
            {
                tokens = await client.AuthorizeAsync(scopes, interactive: true, ct).ConfigureAwait(false);
            }
            catch (AuthorizeException interactiveFailure)
            {
                _log.LogWarning("Authorize failed for {Resource}: {Error}", resource.Name, interactiveFailure.Error);
                return AuthenticationResult.Failed(
                    interactiveFailure.Error, interactiveFailure.ErrorDescription);
            }
        }
        catch (AuthorizeException ex)
        {
            _log.LogWarning("Authorize failed for {Resource}: {Error}", resource.Name, ex.Error);
            return AuthenticationResult.Failed(ex.Error, ex.ErrorDescription);
        }

        // The browser has the foreground; bring the application back or the user is left
        // staring at a tab wondering what happened (README §8.12).
        _focusRestorer()?.Invoke();

        await StoreAsync(resource, tokens, ct).ConfigureAwait(false);

        User ??= tokens.User;
        return AuthenticationResult.Success(User ?? tokens.User!);
    }

    /// <summary>
    /// Acquires a fresh access token using the refresh token for this resource's
    /// authorization server, persisting the rotated replacement immediately. README §8.8.
    /// </summary>
    private async Task<string> RefreshAsync(ResourceOptions resource, CancellationToken ct)
    {
        if (!_tokens.RefreshTokens.TryGetValue(resource.AuthorizationServerId, out var refreshToken))
            throw new RefreshFailedException("no_refresh_token");

        TokenSet tokens;
        try
        {
            tokens = await ClientFor(resource).RefreshAsync(refreshToken, ct).ConfigureAwait(false);
        }
        catch (AuthorizeException ex)
        {
            throw new RefreshFailedException(ex.Error, ex.ErrorDescription);
        }

        await StoreAsync(resource, tokens, ct).ConfigureAwait(false);

        // A refresh response carries no principal unless it included an ID token. On a
        // session restore (where User is still null) rebuild it from the stored one.
        User ??= tokens.User ?? (_tokens.IdToken is null ? null : IdTokenPrincipal.From(_tokens.IdToken));

        Raise(AuthenticationChangeReason.TokenRefreshed);
        return tokens.AccessToken;
    }

    /// <summary>
    /// Persists the rotated refresh token BEFORE anything else can fail. With rotation
    /// enabled the old token is already dead the moment the response arrives — if the
    /// process dies between here and the write, the user faces an unexplained sign-in on
    /// next launch (README §5.6).
    /// </summary>
    private async Task StoreAsync(ResourceOptions resource, TokenSet tokens, CancellationToken ct)
    {
        if (tokens.RefreshToken is not null || tokens.IdentityToken is not null)
        {
            var refreshTokens = new Dictionary<string, string>(_tokens.RefreshTokens, StringComparer.Ordinal);

            if (tokens.RefreshToken is not null)
                refreshTokens[resource.AuthorizationServerId] = tokens.RefreshToken;

            _tokens = _tokens with
            {
                RefreshTokens = refreshTokens,
                IdToken = tokens.IdentityToken ?? _tokens.IdToken,
                ObtainedAt = DateTimeOffset.UtcNow,
            };

            await _store.SaveAsync(_tokens, ct).ConfigureAwait(false);
        }

        _accessTokens.Set(resource.Name, tokens.AccessToken, tokens.AccessTokenExpiresAt);
    }

    // ── Claims helpers (UI gating only — README §8.13) ───────────────────────

    public bool HasScope(string scope) =>
        User?.FindAll("scp").Any(c =>
            c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                   .Contains(scope, StringComparer.Ordinal)) == true;

    public TimeSpan TimeUntilSessionExpiry()
    {
        var expiry = _accessTokens.ExpiryOf(_options.PrimaryResource.Name);
        return expiry is null ? TimeSpan.Zero : expiry.Value - DateTimeOffset.UtcNow;
    }

    // ── Sign-out (README §11) ────────────────────────────────────────────────

    public async Task SignOutAsync(SignOutScope scope, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);

        string? idToken;
        try
        {
            idToken = _tokens.IdToken;

            // Revoke server-side FIRST — if the process dies after clearing local state,
            // an unrevoked refresh token is left alive in Okta (README §11.1). Every
            // authorization server we hold a token for needs its own revocation call.
            foreach (var (authServerId, token) in _tokens.RefreshTokens)
            {
                if (ClientForAuthServer(authServerId) is { } client)
                    await client.RevokeRefreshTokenAsync(token, ct).ConfigureAwait(false);
            }

            _store.Clear();
            _accessTokens.Clear();
            _tokens = new StoredTokens();
            User = null;
        }
        finally
        {
            _gate.Release();
        }

        Raise(AuthenticationChangeReason.SignedOut);

        if (scope != SignOutScope.Global || idToken is null) return;

        var resource = _options.PrimaryResource;
        var postLogout = $"http://127.0.0.1:{_options.RedirectPorts[0]}{_options.PostLogoutPath}";
        var url = await ClientFor(resource)
            .BuildLogoutUrlAsync(idToken, postLogout, ct)
            .ConfigureAwait(false);

        if (url is null) return;

        try
        {
            // The Okta session cookie lives in the system browser, so that is the only
            // place RP-initiated logout can end it (README §10.1, §11.2).
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not open the browser for global sign-out");
        }
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    /// <summary>
    /// One client per resource. Under Variant B (one authorization server per API) each
    /// resource has its own issuer, keys and refresh token, so clients are not
    /// interchangeable (README §5.2). Always called under <see cref="_gate"/>.
    /// </summary>
    private OpenIdConnectClient ClientFor(ResourceOptions resource)
    {
        if (_clients.TryGetValue(resource.Name, out var existing)) return existing;

        var client = new OpenIdConnectClient(
            new OpenIdConnectClientOptions
            {
                Authority = resource.IssuerFor(_options.Domain),
                ClientId = _options.ClientId,
                RedirectPorts = _options.RedirectPorts,
                RedirectPath = _options.RedirectPath,
            },
            _httpClientFactory,
            _loggerFactory.CreateLogger<OpenIdConnectClient>());

        _clients[resource.Name] = client;
        return client;
    }

    private OpenIdConnectClient? ClientForAuthServer(string authorizationServerId) =>
        _options.Resources.Values.FirstOrDefault(r => r.AuthorizationServerId == authorizationServerId)
            is { } resource
            ? ClientFor(resource)
            : null;

    private void Raise(AuthenticationChangeReason reason) =>
        StateChanged?.Invoke(this, new AuthenticationStateChangedEventArgs(reason, User));

    private static string SubjectOf(ClaimsPrincipal? user) =>
        user?.FindFirst("sub")?.Value ?? "unknown";
}
