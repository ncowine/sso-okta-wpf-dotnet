using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Api.Security.Tests;

/// <summary>
/// Mints tokens locally so tests need no network and no Okta tenant. README §15.3.
/// </summary>
/// <remarks>
/// The test host overrides ONLY the key source. Every other validation parameter comes
/// from production configuration — otherwise the tests validate a configuration that is
/// never deployed, and the CI guards in <see cref="ConfigurationGuardTests"/> become
/// worthless.
/// </remarks>
public sealed class TestTokenFactory
{
    public const string Issuer = "https://test.okta.local/oauth2/default";
    public const string Audience = "api://apia";
    public const string OtherAudience = "api://apib";
    public const string ClientId = "0oaTESTCLIENTID";

    private readonly RSA _rsa = RSA.Create(2048);

    public TestTokenFactory() =>
        SigningKey = new RsaSecurityKey(_rsa) { KeyId = "test-key-1" };

    public RsaSecurityKey SigningKey { get; }

    public string Create(
        string audience = Audience,
        string issuer = Issuer,
        string[]? scopes = null,
        string[]? groups = null,
        string subject = "alice@contoso.com",
        string? uid = "00uTESTUSER",
        DateTime? expires = null,
        DateTime? notBefore = null,
        string algorithm = SecurityAlgorithms.RsaSha256,
        SecurityKey? signingKey = null)
    {
        var now = DateTime.UtcNow;

        var claims = new Dictionary<string, object>
        {
            ["sub"] = subject,
            ["cid"] = ClientId,
            ["ver"] = 1,
            ["jti"] = $"AT.{Guid.NewGuid():N}",
        };

        // Okta emits 'scp' and 'groups' as JSON ARRAYS, not space-delimited strings
        // (README §3.4). Modelling that faithfully is the point of these tests.
        if (scopes is { Length: > 0 }) claims["scp"] = scopes;
        if (groups is { Length: > 0 }) claims["groups"] = groups;
        if (uid is not null) claims["uid"] = uid;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            IssuedAt = now,
            NotBefore = notBefore ?? now,
            Expires = expires ?? now.AddMinutes(15),
            SigningCredentials = new SigningCredentials(signingKey ?? SigningKey, algorithm),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    /// <summary>An ID token: audience is the CLIENT, not an API. An API must reject it (README §3.2).</summary>
    public string CreateIdToken() => Create(audience: ClientId, uid: null);

    /// <summary>A client-credentials token: no user, so no 'uid' (README §7.2, §D.5).</summary>
    public string CreateServiceToken(string[] scopes) =>
        Create(scopes: scopes, subject: ClientId, uid: null);

    /// <summary>A token signed with a DIFFERENT key — signature validation must fail.</summary>
    public string CreateWithForeignKey(string[] scopes)
    {
        var foreign = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "test-key-1" };
        return Create(scopes: scopes, signingKey: foreign);
    }

    /// <summary>An HMAC-signed token — 'alg' confusion. Must be rejected (README §12.2).</summary>
    public string CreateHmacSigned(string[] scopes)
    {
        var symmetric = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)) { KeyId = "test-key-1" };
        return Create(scopes: scopes, algorithm: SecurityAlgorithms.HmacSha256, signingKey: symmetric);
    }
}
