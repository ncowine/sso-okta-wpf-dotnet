using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Corp.Api.Security.Delegation;

public sealed class OktaTokenResponse
{
    [JsonPropertyName("access_token")] public string AccessToken { get; set; } = string.Empty;
    [JsonPropertyName("token_type")] public string TokenType { get; set; } = "Bearer";
    [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    [JsonPropertyName("scope")] public string? Scope { get; set; }
}

public sealed class OktaTokenException(string operation, HttpStatusCode status, string body)
    : Exception($"{operation} failed with {(int)status}: {body}")
{
    public HttpStatusCode StatusCode { get; } = status;
}

/// <summary>
/// Acquires downstream tokens via §7 Pattern 1 (On-Behalf-Of) and Pattern 2
/// (client credentials).
/// </summary>
public interface IOktaTokenService
{
    /// <summary>
    /// Pattern 1 — exchanges a user's token for one addressed to <paramref name="audience"/>,
    /// preserving the user's identity. README §7.1.
    /// </summary>
    Task<string> ExchangeOnBehalfOfAsync(
        string subjectToken, string issuer, string audience, string scope, CancellationToken ct);

    /// <summary>
    /// Pattern 2 — a token for this service acting as itself, with no user. README §7.2.
    /// </summary>
    Task<string> GetServiceTokenAsync(string issuer, string scope, CancellationToken ct);
}

public sealed class OktaTokenService(
    HttpClient http,
    IClientAssertionFactory assertions,
    IMemoryCache cache,
    OktaApiOptions options,
    ILogger<OktaTokenService> log) : IOktaTokenService
{
    private const string GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";
    private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private readonly string _clientId =
        options.Service?.ClientId
        ?? throw new InvalidOperationException("Okta:Service:ClientId is not configured (README §5.3).");

    public async Task<string> ExchangeOnBehalfOfAsync(
        string subjectToken, string issuer, string audience, string scope, CancellationToken ct)
    {
        // The cache key MUST be scoped to the subject, or one user's delegated token is
        // served to another. Hash the token: never use it as a raw key, and never log it.
        var key = $"obo:{Fingerprint(subjectToken)}:{audience}:{scope}";
        if (cache.TryGetValue(key, out string? cached) && cached is not null) return cached;

        var tokenEndpoint = $"{issuer}/v1/token";
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = GrantTokenExchange,
            ["subject_token_type"] = TokenTypeAccessToken,
            ["subject_token"] = subjectToken,
            ["audience"] = audience,
            ["scope"] = scope,
            ["client_id"] = _clientId,
            ["client_assertion_type"] = AssertionType,
            ["client_assertion"] = assertions.Create(tokenEndpoint),
        };

        var token = await PostAsync(tokenEndpoint, form, "Token exchange", ct).ConfigureAwait(false);

        // Expire the cache entry before the token does, and never past the subject
        // token's own expiry — delegated authority must not outlive the authority it
        // was derived from.
        var ttl = TimeSpan.FromSeconds(Math.Max(token.ExpiresIn - 30, 0));
        if (ExpiryOf(subjectToken) is { } subjectExpiry)
        {
            var remaining = subjectExpiry - DateTimeOffset.UtcNow - TimeSpan.FromSeconds(30);
            if (remaining < ttl) ttl = remaining;
        }

        if (ttl > TimeSpan.Zero) cache.Set(key, token.AccessToken, ttl);

        log.LogDebug("Exchanged token for {Audience} (expires in {Seconds}s)", audience, token.ExpiresIn);
        return token.AccessToken;
    }

    public async Task<string> GetServiceTokenAsync(string issuer, string scope, CancellationToken ct)
    {
        // Safe to cache by scope alone: there is no user to leak across.
        var key = $"cc:{issuer}:{scope}";
        if (cache.TryGetValue(key, out string? cached) && cached is not null) return cached;

        var tokenEndpoint = $"{issuer}/v1/token";
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = scope,
            ["client_id"] = _clientId,
            ["client_assertion_type"] = AssertionType,
            ["client_assertion"] = assertions.Create(tokenEndpoint),
        };

        var token = await PostAsync(tokenEndpoint, form, "Client credentials", ct).ConfigureAwait(false);

        var ttl = TimeSpan.FromSeconds(Math.Max(token.ExpiresIn - 60, 0));
        if (ttl > TimeSpan.Zero) cache.Set(key, token.AccessToken, ttl);

        return token.AccessToken;
    }

    private async Task<OktaTokenResponse> PostAsync(
        string endpoint, Dictionary<string, string> form, string operation, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };

        using var response = await http.SendAsync(request, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // The body carries the RFC 6749 error / error_description and, for Okta,
            // an errorId. It does NOT contain tokens, so it is safe to log — and it is
            // the single most useful diagnostic available (README §D.6, §14.3).
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            log.LogError("{Operation} to {Endpoint} failed: {Status} {Body}",
                operation, endpoint, (int)response.StatusCode, body);
            throw new OktaTokenException(operation, response.StatusCode, body);
        }

        return await response.Content.ReadFromJsonAsync<OktaTokenResponse>(ct).ConfigureAwait(false)
               ?? throw new OktaTokenException(operation, response.StatusCode, "empty response body");
    }

    /// <summary>
    /// A short, non-reversible fingerprint used only as a cache key. Never log the input,
    /// and never store the token itself as a key.
    /// </summary>
    private static string Fingerprint(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))[..32];

    private static DateTimeOffset? ExpiryOf(string jwt)
    {
        try
        {
            var validTo = new JsonWebTokenHandler().ReadJsonWebToken(jwt).ValidTo;
            return validTo == default ? null : new DateTimeOffset(validTo, TimeSpan.Zero);
        }
        catch
        {
            return null; // Opaque or unparseable: fall back to the response's own TTL.
        }
    }
}
