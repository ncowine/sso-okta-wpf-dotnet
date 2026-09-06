using System.Diagnostics;
using System.Security.Claims;
using System.Web;
using Common.Authentication.Callback;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Common.Authentication.Protocol;

/// <summary>
/// Speaks OpenID Connect to one authorization server: discovery, sign-in, refresh,
/// revocation, sign-out.
/// </summary>
/// <remarks>
/// <para>
/// This is the only class that knows the protocol exists. It knows nothing about how the
/// response comes back — that is <see cref="IRedirectListener"/>'s job — and nothing about
/// storage or caching. Everything above it deals in users and tokens.
/// </para>
/// <para>
/// Almost all of the protocol handling is Microsoft's, not ours.
/// <see cref="ConfigurationManager{T}"/> does discovery, JWKS caching and key rollover;
/// <see cref="OpenIdConnectMessage"/> builds the authorize and logout URLs and parses both
/// the redirect and the token response. What is left here is the ordering, the PKCE
/// parameters, and the decisions about what to do when something fails.
/// </para>
/// </remarks>
internal sealed class OpenIdConnectClient
{
    /// <summary>The named <c>HttpClient</c> used for protocol calls. Has no token handler attached.</summary>
    public const string HttpClientName = "Common.Authentication";

    private readonly AuthenticationOptions _options;
    private readonly IRedirectListener _redirects;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger _log;
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _metadata;

    public OpenIdConnectClient(
        AuthenticationOptions options,
        IRedirectListener redirects,
        IHttpClientFactory httpClientFactory,
        ILogger log)
    {
        _options = options;
        _redirects = redirects;
        _httpClientFactory = httpClientFactory;
        _log = log;

        _metadata = new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{options.Authority.TrimEnd('/')}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(httpClientFactory.CreateClient(HttpClientName))
            {
                // This document carries the keys we validate every token against. Over
                // plaintext, anyone on the network could swap in their own.
                RequireHttps = true,
            });
    }

    /// <summary>
    /// Runs a full sign-in: open the browser, wait for the user to come back, redeem the
    /// code.
    /// </summary>
    /// <param name="interactive">
    /// <c>false</c> sends <c>prompt=none</c>: complete silently from the browser's existing
    /// session, or fail with <c>login_required</c> and show the user nothing.
    /// <para>
    /// This is the whole trick behind "why didn't it ask me again". If the user signed in
    /// to the web dashboard this morning, their browser holds the provider's session
    /// cookie, and this succeeds without a visible prompt.
    /// </para>
    /// </param>
    public async Task<TokenSet> SignInAsync(
        IReadOnlyList<string> scopes, bool interactive, CancellationToken cancellationToken)
    {
        var configuration = await _metadata.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

        var verifier = Pkce.NewVerifier();
        var state = Pkce.NewState();
        var nonce = Pkce.NewNonce();

        var request = new OpenIdConnectMessage
        {
            IssuerAddress = configuration.AuthorizationEndpoint,
            ClientId = _options.ClientId,
            ResponseType = OpenIdConnectResponseType.Code,
            RedirectUri = _redirects.RedirectUri,
            Scope = string.Join(' ', scopes),
            State = state,
            Nonce = nonce,
        };

        // PKCE is not modelled as a property, so it goes through the parameter bag. Always
        // sent, never configurable: it is what makes a client with no secret safe.
        request.SetParameter("code_challenge", Pkce.Challenge(verifier));
        request.SetParameter("code_challenge_method", "S256");

        if (!interactive) request.Prompt = "none";

        // Start waiting before opening the browser. The other order is a race: a cached
        // session can complete the round trip faster than we get here.
        var callback = _redirects.WaitForCallbackAsync(_options.SignInTimeout, cancellationToken);

        OpenBrowser(request.CreateAuthenticationRequestUrl());

        string query;
        try
        {
            query = await callback.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AuthenticationException("timed_out", "The sign-in was not completed in time.");
        }

        var code = ReadAuthorizeResponse(query, state);

        var token = new OpenIdConnectMessage
        {
            GrantType = OpenIdConnectGrantTypes.AuthorizationCode,
            Code = code,

            // Must be byte-for-byte what we sent to /authorize, or the exchange is
            // rejected. This is a common source of "it worked yesterday".
            RedirectUri = _redirects.RedirectUri,
            ClientId = _options.ClientId,
        };

        token.SetParameter("code_verifier", verifier);

        var response = await PostToTokenEndpointAsync(configuration.TokenEndpoint, token, cancellationToken)
            .ConfigureAwait(false);

        var user = await ValidateIdentityTokenAsync(response, configuration, nonce, cancellationToken)
            .ConfigureAwait(false);

        return TokenSet.From(response, user);
    }

    /// <summary>
    /// Trades a refresh token for a new access token, and — where the provider rotates
    /// them — a replacement refresh token.
    /// </summary>
    public async Task<TokenSet> RefreshAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var configuration = await _metadata.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

        var request = new OpenIdConnectMessage
        {
            GrantType = OpenIdConnectGrantTypes.RefreshToken,
            RefreshToken = refreshToken,
            ClientId = _options.ClientId,
        };

        var response = await PostToTokenEndpointAsync(configuration.TokenEndpoint, request, cancellationToken)
            .ConfigureAwait(false);

        // A refresh need not return an ID token. When it does, it is the freshest word on
        // who the user is, so prefer it. There is no nonce to check: there was no
        // authorize request to bind this to.
        var user = string.IsNullOrEmpty(response.IdToken)
            ? null
            : await ValidateIdentityTokenAsync(response, configuration, expectedNonce: null, cancellationToken)
                .ConfigureAwait(false);

        return TokenSet.From(response, user);
    }

    /// <summary>
    /// Asks the provider to invalidate a refresh token (RFC 7009).
    /// </summary>
    /// <remarks>
    /// Best-effort on purpose. The endpoint answers 200 even for a token that was already
    /// invalid, so a failure here means the network, not the token — and it must never
    /// stop a user signing out locally.
    /// </remarks>
    public async Task RevokeRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken)
    {
        try
        {
            var configuration = await _metadata.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

            var endpoint = configuration.AdditionalData.TryGetValue("revocation_endpoint", out var value)
                ? value?.ToString()
                : null;

            if (string.IsNullOrEmpty(endpoint))
            {
                _log.LogDebug("The provider publishes no revocation endpoint; signing out locally only");
                return;
            }

            using var http = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await http.PostAsync(
                endpoint,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["token"] = refreshToken,
                    ["token_type_hint"] = "refresh_token",
                    ["client_id"] = _options.ClientId,
                }),
                cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                _log.LogWarning("Revocation returned {Status}", (int)response.StatusCode);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not revoke the refresh token; continuing to sign out locally");
        }
    }

    /// <summary>
    /// Opens the provider's sign-out page in the browser, ending the session there.
    /// </summary>
    /// <remarks>
    /// It has to be the system browser: that is where the session cookie lives, and it is
    /// the only place it can be cleared.
    /// </remarks>
    public async Task SignOutOfProviderAsync(string identityToken, CancellationToken cancellationToken)
    {
        var configuration = await _metadata.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrEmpty(configuration.EndSessionEndpoint))
        {
            _log.LogInformation("The provider publishes no sign-out endpoint; local sign-out only");
            return;
        }

        var request = new OpenIdConnectMessage
        {
            IssuerAddress = configuration.EndSessionEndpoint,
            IdTokenHint = identityToken,
            PostLogoutRedirectUri = _options.PostLogoutRedirectUri ?? _redirects.RedirectUri,
        };

        OpenBrowser(request.CreateLogoutRequestUrl());
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// <summary>
    /// Hands the URL to the user's default browser.
    /// </summary>
    /// <remarks>
    /// <c>UseShellExecute</c> is what makes this the <i>real</i> browser rather than
    /// something we host. That matters more than it looks: the real browser is where the
    /// provider's session cookie lives, so it is the only thing that can sign the user in
    /// without asking. An embedded control has its own empty cookie jar and will prompt
    /// every single time.
    /// </remarks>
    private void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            throw new AuthenticationException(
                "no_browser",
                "No default browser is set on this machine, or it could not be started.",
                ex);
        }
    }

    /// <summary>Reads the callback query, checking <c>state</c> before trusting anything else in it.</summary>
    private static string ReadAuthorizeResponse(string query, string expectedState)
    {
        var response = new OpenIdConnectMessage(HttpUtility.ParseQueryString(query));

        // Checked first, deliberately. An unsolicited callback should be discarded, not
        // processed and then questioned.
        if (!Pkce.ValuesMatch(response.State, expectedState))
        {
            throw new AuthenticationException(
                "invalid_state",
                "The response did not match this sign-in request and was discarded.");
        }

        if (!string.IsNullOrEmpty(response.Error))
        {
            throw new AuthenticationException(response.Error, response.ErrorDescription);
        }

        return string.IsNullOrEmpty(response.Code)
            ? throw new AuthenticationException(
                "no_authorization_code", "The provider returned no authorization code.")
            : response.Code;
    }

    /// <summary>
    /// Posts a request to the token endpoint and returns the parsed response.
    /// </summary>
    /// <remarks>
    /// Both directions are <see cref="OpenIdConnectMessage"/>: the request's parameter bag
    /// becomes the form body, and the JSON that comes back is parsed by the same type.
    /// </remarks>
    private async Task<OpenIdConnectMessage> PostToTokenEndpointAsync(
        string endpoint, OpenIdConnectMessage request, CancellationToken cancellationToken)
    {
        using var http = _httpClientFactory.CreateClient(HttpClientName);

        using var httpResponse = await http
            .PostAsync(endpoint, new FormUrlEncodedContent(request.Parameters), cancellationToken)
            .ConfigureAwait(false);

        var body = await httpResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        OpenIdConnectMessage response;
        try
        {
            response = new OpenIdConnectMessage(body);
        }
        catch (Exception)
        {
            throw new AuthenticationException(
                "invalid_token_response", "The token endpoint returned a body we could not read.");
        }

        if (!httpResponse.IsSuccessStatusCode || !string.IsNullOrEmpty(response.Error))
        {
            // The body carries the provider's error code and description. It contains no
            // token, so it is safe to surface — and it is by far the most useful thing
            // available when something is misconfigured.
            throw new AuthenticationException(
                string.IsNullOrEmpty(response.Error) ? "token_request_failed" : response.Error,
                response.ErrorDescription
                    ?? $"The token endpoint returned {(int)httpResponse.StatusCode}.");
        }

        return response;
    }

    /// <summary>
    /// Validates the ID token, refreshing the provider's keys once and retrying if it does
    /// not verify — which is what a key rollover looks like from here.
    /// </summary>
    private async Task<ClaimsPrincipal> ValidateIdentityTokenAsync(
        OpenIdConnectMessage response,
        OpenIdConnectConfiguration configuration,
        string? expectedNonce,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(response.IdToken))
        {
            throw new AuthenticationException(
                "no_identity_token",
                "The provider returned no ID token. Check that 'openid' is in the requested scopes.");
        }

        try
        {
            return await IdentityTokenValidator
                .ValidateAsync(response.IdToken, configuration, _options.ClientId, expectedNonce)
                .ConfigureAwait(false);
        }
        catch (AuthenticationException) when (expectedNonce is not null)
        {
            _log.LogInformation(
                "The identity token did not verify against the cached signing keys; " +
                "refreshing provider metadata and trying once more");

            _metadata.RequestRefresh();
            var refreshed = await _metadata.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

            return await IdentityTokenValidator
                .ValidateAsync(response.IdToken, refreshed, _options.ClientId, expectedNonce)
                .ConfigureAwait(false);
        }
    }
}

/// <summary>What a successful call yields, with the expiry already turned into a moment in time.</summary>
internal sealed record TokenSet(
    string AccessToken,
    DateTimeOffset ExpiresAt,
    string? RefreshToken,
    string? IdentityToken,
    ClaimsPrincipal? User)
{
    /// <summary>
    /// If the provider omits <c>expires_in</c>, assume a short life rather than a long
    /// one. Renewing sooner than necessary costs a round trip; assuming too long means
    /// presenting an expired token and failing a user's request.
    /// </summary>
    private static readonly TimeSpan CautiousDefault = TimeSpan.FromMinutes(5);

    public static TokenSet From(OpenIdConnectMessage response, ClaimsPrincipal? user)
    {
        if (string.IsNullOrEmpty(response.AccessToken))
        {
            throw new AuthenticationException("no_access_token", "The provider returned no access token.");
        }

        var lifetime = int.TryParse(response.ExpiresIn, out var seconds)
            ? TimeSpan.FromSeconds(seconds)
            : CautiousDefault;

        return new TokenSet(
            response.AccessToken,
            DateTimeOffset.UtcNow.Add(lifetime),
            response.RefreshToken,
            response.IdToken,
            user);
    }
}
