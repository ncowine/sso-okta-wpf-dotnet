using System.Diagnostics;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Claims;
using Duende.IdentityModel.OidcClient;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Corp.Identity.Client;

/// <summary>
/// Authorization Code + PKCE against an Okta Custom Authorization Server, via the system
/// browser and a loopback redirect. README §8.7, §8.8, §8.9.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OktaAuthenticationService : IAuthenticationService, IDisposable
{
    private readonly OktaClientOptions _options;
    private readonly ITokenStore _store;
    private readonly IAccessTokenCache _accessTokens;
    private readonly ILogger<OktaAuthenticationService> _log;
    private readonly ILoggerFactory _loggerFactory;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly Func<Action?> _focusRestorer;

    /// <summary>
    /// Serialises token acquisition. NOT optional: a Prism shell routinely fires several
    /// view models' loads on navigation. Without this they race into simultaneous refresh
    /// calls with the SAME rotating refresh token — and with rotation enabled the second
    /// presents an already-rotated token, which Okta reads as replay and can invalidate
    /// the whole family, signing the user out for no reason. README §8.7.
    /// </summary>
    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly Dictionary<string, OidcClient> _clients = new(StringComparer.Ordinal);
    private StoredTokens _tokens = new();
    private bool _disposed;

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
            var resource = _options.PrimaryResource;
            var result = await AuthorizeAsync(resource, allowInteractive: true, ct).ConfigureAwait(false);

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
            {
                throw new RefreshFailedException(
                    result.Error ?? "authorize_failed", result.ErrorDescription);
            }

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
    /// Runs an authorization-code flow for one resource, trying <c>prompt=none</c> first.
    /// </summary>
    /// <remarks>
    /// <c>prompt=none</c> is what makes this safe to attempt automatically: Okta either
    /// completes silently against the existing session cookie, or returns
    /// <c>login_required</c> — it never surprises the user with a browser window mid
    /// workflow (README §8.9, §10.1).
    /// </remarks>
    private async Task<AuthenticationResult> AuthorizeAsync(
        ResourceOptions resource, bool allowInteractive, CancellationToken ct)
    {
        var client = ClientFor(resource);

        var silent = new LoginRequest();
        silent.FrontChannelExtraParameters.Add("prompt", "none");

        var result = await client.LoginAsync(silent, ct).ConfigureAwait(false);

        if (result.IsError && IsInteractionRequired(result.Error))
        {
            if (!allowInteractive)
                return AuthenticationResult.Failed(result.Error, result.ErrorDescription);

            _log.LogInformation("Silent authorize returned {Error}; prompting interactively", result.Error);
            result = await client.LoginAsync(new LoginRequest(), ct).ConfigureAwait(false);
        }

        if (result.IsError)
        {
            _log.LogWarning("Authorize failed for {Resource}: {Error} {Description}",
                resource.Name, result.Error, result.ErrorDescription);

            return AuthenticationResult.Failed(result.Error, result.ErrorDescription);
        }

        if (result.RefreshToken is not null)
        {
            var refreshTokens = new Dictionary<string, string>(_tokens.RefreshTokens, StringComparer.Ordinal)
            {
                [resource.AuthorizationServerId] = result.RefreshToken,
            };

            _tokens = _tokens with
            {
                RefreshTokens = refreshTokens,
                IdToken = result.IdentityToken ?? _tokens.IdToken,
                ObtainedAt = DateTimeOffset.UtcNow,
            };

            await _store.SaveAsync(_tokens, ct).ConfigureAwait(false);
        }

        _accessTokens.Set(resource.Name, result.AccessToken, result.AccessTokenExpiration);

        // Identity comes from the ID token (README §3.2). OidcClient has already validated
        // its signature, issuer, audience and nonce.
        User ??= result.User;

        return AuthenticationResult.Success(User ?? result.User);
    }

    private static bool IsInteractionRequired(string? error) =>
        error is "login_required" or "interaction_required" or "consent_required"
              or "account_selection_required";

    /// <summary>
    /// Acquires a fresh access token using the refresh token for this resource's
    /// authorization server, persisting the rotated replacement immediately. README §8.8.
    /// </summary>
    private async Task<string> RefreshAsync(ResourceOptions resource, CancellationToken ct)
    {
        if (!_tokens.RefreshTokens.TryGetValue(resource.AuthorizationServerId, out var refreshToken))
            throw new RefreshFailedException("no_refresh_token");

        var client = ClientFor(resource);
        var result = await client
            .RefreshTokenAsync(refreshToken, cancellationToken: ct)
            .ConfigureAwait(false);

        if (result.IsError) throw new RefreshFailedException(result.Error ?? "unknown", result.ErrorDescription);

        // Rotation: Okta returns a NEW refresh token and invalidates the old one.
        // Persisting immediately is critical — if the process dies between the response
        // and the write, the stored token is already dead and the user faces an
        // unexplained sign-in on next launch.
        var refreshTokens = new Dictionary<string, string>(_tokens.RefreshTokens, StringComparer.Ordinal)
        {
            [resource.AuthorizationServerId] = result.RefreshToken ?? refreshToken,
        };

        _tokens = _tokens with
        {
            RefreshTokens = refreshTokens,
            IdToken = result.IdentityToken ?? _tokens.IdToken,
            ObtainedAt = DateTimeOffset.UtcNow,
        };
        await _store.SaveAsync(_tokens, ct).ConfigureAwait(false);

        _accessTokens.Set(resource.Name, result.AccessToken, result.AccessTokenExpiration);

        // RefreshTokenResult carries no ClaimsPrincipal, so on a session restore (where
        // User is still null) rebuild it from the ID token. OidcClient has already
        // verified that token's signature and issuer as part of this refresh.
        if (User is null && _tokens.IdToken is not null)
            User = IdTokenPrincipal.From(_tokens.IdToken);

        Raise(AuthenticationChangeReason.TokenRefreshed);
        return result.AccessToken;
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
        var idToken = _tokens.IdToken;
        var refreshTokens = _tokens.RefreshTokens;

        // Revoke server-side FIRST — if the process dies after clearing local state, an
        // unrevoked refresh token is left alive in Okta (README §11.1). Every
        // authorization server we hold a token for needs its own revocation call.
        foreach (var (authServerId, token) in refreshTokens)
            await RevokeAsync(authServerId, token, ct).ConfigureAwait(false);

        _store.Clear();
        _accessTokens.Clear();
        _tokens = new StoredTokens();
        User = null;
        Raise(AuthenticationChangeReason.SignedOut);

        if (scope != SignOutScope.Global || idToken is null) return;

        // RP-initiated logout must happen in the SYSTEM BROWSER — that is where the Okta
        // session cookie lives (README §10.1, §11.2).
        var resource = _options.PrimaryResource;
        var port = _options.RedirectPorts[0];
        var url = $"{resource.IssuerFor(_options.Domain)}/v1/logout" +
                  $"?id_token_hint={Uri.EscapeDataString(idToken)}" +
                  $"&post_logout_redirect_uri={Uri.EscapeDataString($"http://127.0.0.1:{port}{_options.PostLogoutPath}")}";

        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not open the browser for global sign-out");
        }
    }

    private async Task RevokeAsync(string authServerId, string token, CancellationToken ct)
    {
        try
        {
            using var http = _httpClientFactory.CreateClient(nameof(OktaAuthenticationService));

            using var response = await http.PostAsync(
                $"https://{_options.Domain}/oauth2/{authServerId}/v1/revoke",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["token"] = token,
                    ["token_type_hint"] = "refresh_token",
                    ["client_id"] = _options.ClientId,
                }),
                ct).ConfigureAwait(false);

            // RFC 7009: the endpoint returns 200 even for an already-invalid token, so a
            // non-200 here is a network problem and must not block sign-out (README §D.10).
            if (!response.IsSuccessStatusCode)
                _log.LogWarning("Refresh token revocation returned {Status}", (int)response.StatusCode);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Refresh token revocation failed; continuing with local sign-out");
        }
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    /// <summary>
    /// One OidcClient per resource. Under Variant B (one authorization server per API)
    /// each resource has its own issuer, so clients are not interchangeable (README §5.2).
    /// </summary>
    private OidcClient ClientFor(ResourceOptions resource)
    {
        if (_clients.TryGetValue(resource.Name, out var existing)) return existing;

        var port = _options.RedirectPorts[0];
        var browser = new LoopbackBrowser(
            _options.RedirectPorts,
            _options.RedirectPath,
            _loggerFactory.CreateLogger<LoopbackBrowser>(),
            _focusRestorer());

        var client = new OidcClient(new OidcClientOptions
        {
            Authority = resource.IssuerFor(_options.Domain),
            ClientId = _options.ClientId,

            // Public client: PKCE only, no secret. Set explicitly so nobody "adds the
            // missing secret" later (README §E.3).
            ClientSecret = null,

            RedirectUri = $"http://127.0.0.1:{port}{_options.RedirectPath}",
            PostLogoutRedirectUri = $"http://127.0.0.1:{port}{_options.PostLogoutPath}",
            Scope = string.Join(' ', _options.Scopes.Concat(resource.Scopes).Distinct(StringComparer.Ordinal)),
            Browser = browser,
            LoggerFactory = _loggerFactory,
            Policy = new Policy
            {
                // Never accept an unsigned or unverifiable ID token.
                RequireIdentityTokenSignature = true,
                ValidateTokenIssuerName = true,
                RequireAccessTokenHash = false, // Okta omits at_hash on some flows
            },
        });

        _clients[resource.Name] = client;
        return client;
    }

    private void Raise(AuthenticationChangeReason reason) =>
        StateChanged?.Invoke(this, new AuthenticationStateChangedEventArgs(reason, User));

    private static string SubjectOf(ClaimsPrincipal? user) =>
        user?.FindFirst("sub")?.Value ?? "(unknown)";

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _gate.Dispose();
    }
}
