using System.Net;
using System.Net.Http.Headers;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Api.Security.Tests;

/// <summary>
/// The tests that earn their keep are the ones asserting what must be REJECTED.
/// A test that a valid token is accepted proves very little — that path is exercised
/// by every manual run. README §15.3.
/// </summary>
public sealed class TokenValidationTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string Endpoint = "orders/whoami";

    [Fact]
    public async Task Accepts_a_valid_token_with_the_required_scope()
    {
        var response = await CallAsync(factory.Tokens.Create(scopes: ["apia.read"]));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_request_with_no_token()
    {
        using var client = factory.CreateClient();
        var response = await client.GetAsync(Endpoint);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_token_minted_for_a_different_audience()
    {
        // The §7.5 anti-pattern: ApiB's token must never be accepted here (README §3.3, Rule 1).
        var response = await CallAsync(
            factory.Tokens.Create(audience: TestTokenFactory.OtherAudience, scopes: ["apia.read"]));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_an_id_token()
    {
        // An ID token's audience is the CLIENT. An API that accepts one cannot know
        // whether the caller was authorised to reach it (README §3.2).
        var response = await CallAsync(factory.Tokens.CreateIdToken());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_token_from_a_different_issuer()
    {
        var response = await CallAsync(factory.Tokens.Create(
            issuer: "https://evil.example.com/oauth2/default", scopes: ["apia.read"]));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_an_expired_token()
    {
        var response = await CallAsync(factory.Tokens.Create(
            scopes: ["apia.read"], expires: DateTime.UtcNow.AddMinutes(-5)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_token_that_is_not_yet_valid()
    {
        // The clock-skew failure from README §13.5, made deterministic.
        var response = await CallAsync(factory.Tokens.Create(
            scopes: ["apia.read"],
            notBefore: DateTime.UtcNow.AddMinutes(5),
            expires: DateTime.UtcNow.AddMinutes(20)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_token_signed_with_an_unknown_key()
    {
        var response = await CallAsync(factory.Tokens.CreateWithForeignKey(["apia.read"]));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_an_hmac_signed_token()
    {
        // 'alg' confusion: an attacker signs with HMAC using the public key as the
        // secret. ValidAlgorithms pinned to RS256 is what blocks this (README §12.2).
        var response = await CallAsync(factory.Tokens.CreateHmacSigned(["apia.read"]));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_tampered_payload()
    {
        var token = factory.Tokens.Create(scopes: ["apia.read"]);
        var parts = token.Split('.');
        var tampered = $"{parts[0]}.{parts[1][..^4]}AAAA.{parts[2]}";

        var response = await CallAsync(tampered);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_valid_token_that_lacks_the_required_scope()
    {
        // 403, not 401: the token is fine, so telling the client to refresh and retry
        // would send it into a pointless loop (README §9.6).
        var response = await CallAsync(factory.Tokens.Create(scopes: ["apia.write"]));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_service_token_on_a_user_only_endpoint()
    {
        // A client-credentials token carries broader authority than any single user.
        // Serving a user-initiated request with one silently escalates every user's
        // privileges (README §7.2).
        var token = factory.Tokens.CreateServiceToken(["apia.read"]);
        var response = await CallAsync(
            token, "orders/11111111-1111-1111-1111-111111111111/billing");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Filters_records_by_group_membership()
    {
        // Scope says the token may read; the group says which records (README §9.3).
        var token = factory.Tokens.Create(scopes: ["apia.read"], groups: ["App-Warehouse"]);
        var response = await CallAsync(token, "orders");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Widget assembly", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Consulting retainer", body, StringComparison.Ordinal);
    }

    private async Task<HttpResponseMessage> CallAsync(string token, string path = Endpoint)
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return await client.SendAsync(request);
    }
}
