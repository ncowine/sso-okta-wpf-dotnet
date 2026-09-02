using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Web;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Corp.Identity.Protocol;

/// <summary>
/// Authorization Code + PKCE against one OIDC authorization server, using the system
/// browser and a loopback redirect. README §4.1, §8.5, §8.7.
/// </summary>
/// <remarks>
/// <para>One instance per authorization server. Under Variant B (one server per API) a
/// client that talks to two APIs holds two of these, because an issuer, its keys and its
/// refresh tokens are not interchangeable (README §5.2).</para>
/// <para>Discovery and JWKS come from
/// <see cref="ConfigurationManager{T}"/>, which caches the document, refreshes it on a
/// schedule, and can be told to refresh early when a signature fails against the keys it
/// holds — the key-rollover case.</para>
/// </remarks>
internal sealed class OpenIdConnectClient
{
    /// <summary>
    /// How long to wait for the user to complete sign-in in the browser before giving up.
    /// Long enough for a password plus MFA prompt, short enough that an abandoned attempt
    /// does not hold a port for the life of the process.
    /// </summary>
    private static readonly TimeSpan BrowserTimeout = TimeSpan.FromMinutes(5);

    private readonly OpenIdConnectClientOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger _log;
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _configuration;

    public OpenIdConnectClient(
        OpenIdConnectClientOptions options,
        IHttpClientFactory httpClientFactory,
        ILogger log)
    {
        _options = options;
        _httpClientFactory = httpClientFactory;
        _log = log;

        _configuration = new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{options.Authority.TrimEnd('/')}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(httpClientFactory.CreateClient(HttpClientName))
            {
                // Metadata carries signing keys. Fetching it over plaintext would let a
                // network attacker choose the keys we validate against.
                RequireHttps = true,
            });
    }

    public const string HttpClientName = "Corp.Identity";

    /// <summary>
    /// Runs an authorize + token round trip through the system browser.
    /// </summary>
    /// <param name="interactive">
    /// When false the request carries <c>prompt=none</c>: succeed silently from the
    /// existing session cookie, or fail with <c>login_required</c> and never show a
    /// window. This is what acquires a token for a SECOND authorization server without
    /// asking the user again (README §8.9), and what makes cross-application SSO silent
    /// (README §10.1).
    /// </param>
    public async Task<TokenSet> AuthorizeAsync(
        IReadOnlyList<string> scopes, bool interactive, CancellationToken ct)
    {
        var configuration = await _configuration.GetConfigurationAsync(ct).ConfigureAwait(false);

        // Bind FIRST, so the redirect_uri we send names the port we are actually on.
        using var listener = new LoopbackListener(_options.RedirectPorts, _options.RedirectPath, _log);

        var verifier = Pkce.NewVerifier();
        var state = Pkce.NewState();
        var nonce = Pkce.NewNonce();

        var authorizeUrl = BuildAuthorizeUrl(
            configuration.AuthorizationEndpoint, listener.RedirectUri, scopes,
            verifier, state, nonce, interactive);

        LaunchBrowser(authorizeUrl);

        var query = await listener.WaitForCallbackAsync(BrowserTimeout, ct).ConfigureAwait(false);
        var code = ReadAuthorizeResponse(query, state);

        var tokens = await PostToTokenEndpointAsync(
            configuration.TokenEndpoint,
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,

                // Must be byte-identical to the value sent to /authorize, or the token
                // endpoint rejects the exchange.
                ["redirect_uri"] = listener.RedirectUri,
                ["client_id"] = _options.ClientId,
                ["code_verifier"] = verifier,
            },
            ct).ConfigureAwait(false);

        var user = await ValidateIdentityTokenAsync(tokens, configuration, nonce, ct).ConfigureAwait(false);
        return TokenSet.From(tokens, user);
    }

    /// <summary>
    /// Exchanges a refresh token for a new access token, and — with rotation enabled — a
    /// replacement refresh token. README §5.6, §8.8.
    /// </summary>
    public async Task<TokenSet> RefreshAsync(string refreshToken, CancellationToken ct)
    {
        var configuration = await _configuration.GetConfigurationAsync(ct).ConfigureAwait(false);

        var tokens = await PostToTokenEndpointAsync(
            configuration.TokenEndpoint,
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = _options.ClientId,
            },
            ct).ConfigureAwait(false);

        // A refresh response need not carry an ID token. When it does, it is the freshest
        // statement of who the user is, so prefer it.
        var user = tokens.IdentityToken is null
            ? null
            : await ValidateIdentityTokenAsync(tokens, configuration, expectedNonce: null, ct)
                .ConfigureAwait(false);

        return TokenSet.From(tokens, user);
    }

    /// <summary>
    /// RFC 7009 revocation. Best-effort by design: the endpoint returns 200 even for an
    /// already-invalid token, so a failure here is a network problem and must never block
    /// local sign-out (README §D.10).
    /// </summary>
    public async Task RevokeRefreshTokenAsync(string refreshToken, CancellationToken ct)
    {
        try
        {
            var configuration = await _configuration.GetConfigurationAsync(ct).ConfigureAwait(false);

            var endpoint = configuration.AdditionalData.TryGetValue("revocation_endpoint", out var value)
                ? value?.ToString()
                : $"{_options.Authority.TrimEnd('/')}/v1/revoke";

            if (string.IsNullOrEmpty(endpoint)) return;

            using var http = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await http.PostAsync(
                endpoint,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["token"] = refreshToken,
                    ["token_type_hint"] = "refresh_token",
                    ["client_id"] = _options.ClientId,
                }),
                ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                _log.LogWarning("Refresh token revocation returned {Status}", (int)response.StatusCode);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Refresh token revocation failed; continuing with local sign-out");
        }
    }

    /// <summary>
    /// The RP-initiated logout URL. It must be opened in the SYSTEM BROWSER, because that
    /// is where the session cookie being ended actually lives (README §10.1, §11.2).
    /// </summary>
    public async Task<string?> BuildLogoutUrlAsync(
        string idToken, string postLogoutRedirectUri, CancellationToken ct)
    {
        var configuration = await _configuration.GetConfigurationAsync(ct).ConfigureAwait(false);
        var endpoint = configuration.EndSessionEndpoint;

        if (string.IsNullOrEmpty(endpoint)) return null;

        return $"{endpoint}?id_token_hint={Uri.EscapeDataString(idToken)}" +
               $"&post_logout_redirect_uri={Uri.EscapeDataString(postLogoutRedirectUri)}";
    }

    // ── Internals ────────────────────────────────────────────────────────────

    private string BuildAuthorizeUrl(
        string endpoint, string redirectUri, IReadOnlyList<string> scopes,
        string verifier, string state, string nonce, bool interactive)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);

        query["client_id"] = _options.ClientId;
        query["response_type"] = "code";
        query["redirect_uri"] = redirectUri;
        query["scope"] = string.Join(' ', scopes);
        query["state"] = state;
        query["nonce"] = nonce;
        query["code_challenge"] = Pkce.Challenge(verifier);
        query["code_challenge_method"] = "S256";

        if (!interactive) query["prompt"] = "none";

        return $"{endpoint}?{query}";
    }

    private void LaunchBrowser(string url)
    {
        try
        {
            // UseShellExecute launches the user's DEFAULT browser, which is the one
            // holding the session cookie. An embedded WebView would have its own cookie
            // jar and would defeat SSO entirely (README §4.2).
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            throw new AuthorizeException(
                "browser_unavailable",
                "No default browser is configured on this machine, or it could not be started.",
                ex);
        }
    }

    /// <summary>Reads the redirect query, comparing <c>state</c> before trusting anything in it.</summary>
    private static string ReadAuthorizeResponse(string query, string expectedState)
    {
        var parsed = HttpUtility.ParseQueryString(query);

        // Compare state before reading the code: an unsolicited redirect must be
        // discarded, not processed and then questioned.
        if (!string.Equals(parsed["state"], expectedState, StringComparison.Ordinal))
        {
            throw new AuthorizeException(
                "invalid_state",
                "The redirect did not match this sign-in request and was discarded.");
        }

        if (parsed["error"] is { } error)
            throw new AuthorizeException(error, parsed["error_description"]);

        return parsed["code"]
               ?? throw new AuthorizeException("invalid_response", "No authorization code was returned.");
    }

    private async Task<TokenEndpointResponse> PostToTokenEndpointAsync(
        string endpoint, Dictionary<string, string> form, CancellationToken ct)
    {
        using var http = _httpClientFactory.CreateClient(HttpClientName);
        using var response = await http
            .PostAsync(endpoint, new FormUrlEncodedContent(form), ct)
            .ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // The body carries the RFC 6749 error and, for Okta, an errorId. It holds no
            // token, so it is safe to surface — and it is the single most useful
            // diagnostic available (README §14.3).
            var failure = TryParse(body);
            throw new AuthorizeException(
                failure?.Error ?? "token_request_failed",
                failure?.ErrorDescription ?? $"HTTP {(int)response.StatusCode}");
        }

        return TryParse(body)
               ?? throw new AuthorizeException("invalid_response", "The token endpoint returned no body.");
    }

    private static TokenEndpointResponse? TryParse(string body)
    {
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<TokenEndpointResponse>(body);
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Validates the ID token, refreshing the discovery document once if the signature
    /// does not verify against the keys currently held — that is what a key rollover
    /// looks like from here.
    /// </summary>
    private async Task<ClaimsPrincipal> ValidateIdentityTokenAsync(
        TokenEndpointResponse tokens,
        OpenIdConnectConfiguration configuration,
        string? expectedNonce,
        CancellationToken ct)
    {
        var idToken = tokens.IdentityToken
                      ?? throw new AuthorizeException(
                          "no_id_token", "The token endpoint returned no identity token.");

        // On a refresh there is no authorize request to bind to, so there is no nonce to
        // compare. The token still had to arrive over TLS from the token endpoint in
        // response to a refresh token only this client holds.
        var nonce = expectedNonce ?? ReadNonce(idToken);

        try
        {
            return await IdentityTokenValidator
                .ValidateAsync(idToken, configuration, _options.ClientId, nonce)
                .ConfigureAwait(false);
        }
        catch (IdentityTokenException)
        {
            _log.LogInformation(
                "Identity token did not validate against the cached signing keys; " +
                "refreshing metadata and retrying once (key rollover)");

            _configuration.RequestRefresh();
            var refreshed = await _configuration.GetConfigurationAsync(ct).ConfigureAwait(false);

            return await IdentityTokenValidator
                .ValidateAsync(idToken, refreshed, _options.ClientId, nonce)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reads the nonce out of a token so the refresh path can satisfy the validator's
    /// comparison. Safe only because the token's signature is verified immediately after.
    /// </summary>
    private static string ReadNonce(string idToken)
    {
        var jwt = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler()
            .ReadJsonWebToken(idToken);

        return jwt.TryGetPayloadValue<string>("nonce", out var nonce) ? nonce : string.Empty;
    }
}

internal sealed record OpenIdConnectClientOptions
{
    public required string Authority { get; init; }
    public required string ClientId { get; init; }
    public required IReadOnlyList<int> RedirectPorts { get; init; }
    public required string RedirectPath { get; init; }
}

/// <summary>The token endpoint's response, in the shape RFC 6749 and OIDC define it.</summary>
internal sealed record TokenEndpointResponse
{
    [JsonPropertyName("access_token")] public string? AccessToken { get; init; }
    [JsonPropertyName("id_token")] public string? IdentityToken { get; init; }
    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; init; }
    [JsonPropertyName("expires_in")] public int ExpiresIn { get; init; }
    [JsonPropertyName("scope")] public string? Scope { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
    [JsonPropertyName("error_description")] public string? ErrorDescription { get; init; }
}

/// <summary>What a successful flow yields, with the expiry already turned into an instant.</summary>
internal sealed record TokenSet(
    string AccessToken,
    DateTimeOffset AccessTokenExpiresAt,
    string? RefreshToken,
    string? IdentityToken,
    ClaimsPrincipal? User)
{
    public static TokenSet From(TokenEndpointResponse response, ClaimsPrincipal? user) => new(
        response.AccessToken
            ?? throw new AuthorizeException("no_access_token", "The token endpoint returned no access token."),
        DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
        response.RefreshToken,
        response.IdentityToken,
        user);
}

/// <summary>
/// A protocol-level failure carrying the authorization server's own error code, so callers
/// can distinguish "sign in again" (<c>login_required</c>) from a real fault.
/// </summary>
public sealed class AuthorizeException(string error, string? description = null, Exception? inner = null)
    : Exception($"{error}{(description is null ? "" : $": {description}")}", inner)
{
    public string Error { get; } = error;
    public string? ErrorDescription { get; } = description;

    /// <summary>The set Okta returns when <c>prompt=none</c> cannot be satisfied (README §8.9).</summary>
    public bool IsInteractionRequired =>
        Error is "login_required" or "interaction_required" or "consent_required"
              or "account_selection_required";
}
