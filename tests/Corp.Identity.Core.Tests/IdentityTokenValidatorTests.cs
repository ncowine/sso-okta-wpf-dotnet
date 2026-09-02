using System.Security.Cryptography;
using Corp.Identity.Protocol;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Identity.Core.Tests;

/// <summary>
/// Weighted towards what must be REJECTED (README §15.3). An ID token that passes when it
/// should not is the difference between knowing who the user is and taking their word
/// for it.
/// </summary>
public class IdentityTokenValidatorTests : IDisposable
{
    private const string Issuer = "https://localhost:7100/oauth2/apia-as";
    private const string ClientId = "appa-client";
    private const string Nonce = "n-0S6_WzA2Mj";

    private readonly RSA _key = RSA.Create(2048);
    private readonly RSA _otherKey = RSA.Create(2048);

    private OpenIdConnectConfiguration Configuration(RSA? key = null)
    {
        var configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
        configuration.SigningKeys.Add(new RsaSecurityKey(key ?? _key) { KeyId = "test-key" });
        return configuration;
    }

    private string Token(
        string? issuer = null,
        string? audience = null,
        string? nonce = Nonce,
        RSA? signingKey = null,
        DateTime? expires = null,
        DateTime? notBefore = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "00udevalice",
            ["preferred_username"] = "alice@contoso.com",
        };

        if (nonce is not null) claims["nonce"] = nonce;

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer ?? Issuer,
            Audience = audience ?? ClientId,
            Claims = claims,
            NotBefore = notBefore ?? DateTime.UtcNow.AddMinutes(-1),
            Expires = expires ?? DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(signingKey ?? _key) { KeyId = "test-key" },
                SecurityAlgorithms.RsaSha256),
        });
    }

    [Fact]
    public async Task Accepts_a_well_formed_token_and_surfaces_the_subject()
    {
        var user = await IdentityTokenValidator.ValidateAsync(
            Token(), Configuration(), ClientId, Nonce);

        Assert.Equal("00udevalice", user.FindFirst("sub")?.Value);

        // NameClaimType is "sub", mirroring the API side, so the same claim identifies
        // the user on both sides of the wire (README §9.2).
        Assert.Equal("00udevalice", user.Identity?.Name);
    }

    [Fact]
    public async Task Rejects_a_token_addressed_to_a_different_client()
    {
        // An access token for another application, or an ID token minted for AppB,
        // must not be accepted as proof of identity here.
        await Assert.ThrowsAsync<IdentityTokenException>(() => IdentityTokenValidator.ValidateAsync(
            Token(audience: "appb-client"), Configuration(), ClientId, Nonce));
    }

    [Fact]
    public async Task Rejects_a_token_from_a_foreign_issuer()
    {
        await Assert.ThrowsAsync<IdentityTokenException>(() => IdentityTokenValidator.ValidateAsync(
            Token(issuer: "https://evil.example.com/oauth2/apia-as"), Configuration(), ClientId, Nonce));
    }

    [Fact]
    public async Task Rejects_a_token_signed_by_a_key_the_server_does_not_publish()
    {
        await Assert.ThrowsAsync<IdentityTokenException>(() => IdentityTokenValidator.ValidateAsync(
            Token(signingKey: _otherKey), Configuration(), ClientId, Nonce));
    }

    [Fact]
    public async Task Rejects_an_expired_token_beyond_the_clock_skew_allowance()
    {
        await Assert.ThrowsAsync<IdentityTokenException>(() => IdentityTokenValidator.ValidateAsync(
            Token(notBefore: DateTime.UtcNow.AddMinutes(-30), expires: DateTime.UtcNow.AddMinutes(-10)),
            Configuration(), ClientId, Nonce));
    }

    [Fact]
    public async Task Rejects_a_token_whose_nonce_belongs_to_a_different_request()
    {
        // Signature and issuer prove the token is genuine. Only the nonce proves it was
        // minted for THIS authorize request rather than captured from another one.
        var ex = await Assert.ThrowsAsync<IdentityTokenException>(() => IdentityTokenValidator.ValidateAsync(
            Token(nonce: "some-other-flows-nonce"), Configuration(), ClientId, Nonce));

        Assert.Contains("nonce", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Rejects_a_token_carrying_no_nonce_at_all()
    {
        await Assert.ThrowsAsync<IdentityTokenException>(() => IdentityTokenValidator.ValidateAsync(
            Token(nonce: null), Configuration(), ClientId, Nonce));
    }

    [Fact]
    public async Task Failure_messages_never_contain_the_token()
    {
        var token = Token(audience: "appb-client");

        var ex = await Assert.ThrowsAsync<IdentityTokenException>(() => IdentityTokenValidator.ValidateAsync(
            token, Configuration(), ClientId, Nonce));

        // Validation failures get logged and shown. A message carrying the token turns a
        // diagnostic into a credential leak (README §D.6).
        Assert.DoesNotContain(token, ex.Message);
    }

    public void Dispose()
    {
        _key.Dispose();
        _otherKey.Dispose();
        GC.SuppressFinalize(this);
    }
}
