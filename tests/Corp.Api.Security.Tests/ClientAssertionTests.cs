using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Corp.Api.Security.Delegation;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Api.Security.Tests;

/// <summary>
/// Covers the private_key_jwt assertion (README §7.1, §4.4) without touching the machine
/// certificate store — the certificate source is injected via
/// <see cref="ISigningCertificateProvider"/>.
/// </summary>
public sealed class ClientAssertionTests
{
    private const string ClientId = "0oaTESTSERVICE";
    private const string TokenEndpoint = "https://dev-12345678.okta.com/oauth2/aus123/v1/token";

    private static (X509ClientAssertionFactory Factory, X509Certificate2 Cert) Create()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test-Okta-ClientAuth", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var options = new ServiceIdentityOptions
        {
            ClientId = ClientId,
            SigningCertificateThumbprint = cert.Thumbprint,
        };

        return (new X509ClientAssertionFactory(options, new StubProvider(cert)), cert);
    }

    [Fact]
    public void Assertion_is_addressed_to_the_token_endpoint()
    {
        var (factory, cert) = Create();
        using var _ = cert;

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(factory.Create(TokenEndpoint));

        // Okta requires the assertion audience to be the EXACT token endpoint URL.
        // A mismatch is the most common cause of 'invalid_client' (README §14.3).
        Assert.Contains(TokenEndpoint, jwt.Audiences);
        Assert.Equal(ClientId, jwt.Issuer);
        Assert.Equal(ClientId, jwt.GetClaim("sub").Value);
    }

    [Fact]
    public void Assertion_is_signed_with_rs256_and_verifies_against_the_public_key()
    {
        var (factory, cert) = Create();
        using var _ = cert;

        var token = factory.Create(TokenEndpoint);

        var result = new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = ClientId,
            ValidateAudience = true,
            ValidAudience = TokenEndpoint,
            ValidateLifetime = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            IssuerSigningKey = new X509SecurityKey(cert),
        }).GetAwaiter().GetResult();

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public void Each_assertion_carries_a_unique_jti()
    {
        var (factory, cert) = Create();
        using var _ = cert;

        var handler = new JsonWebTokenHandler();
        var first = handler.ReadJsonWebToken(factory.Create(TokenEndpoint)).GetClaim("jti").Value;
        var second = handler.ReadJsonWebToken(factory.Create(TokenEndpoint)).GetClaim("jti").Value;

        // Replay protection: Okta rejects a reused jti.
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Assertion_lifetime_is_short()
    {
        var (factory, cert) = Create();
        using var _ = cert;

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(factory.Create(TokenEndpoint));

        Assert.True(jwt.ValidTo - jwt.ValidFrom <= TimeSpan.FromMinutes(5),
            "Client assertions must be short-lived; Okta caps this regardless.");
    }

    [Fact]
    public void Rejects_an_empty_token_endpoint()
    {
        var (factory, cert) = Create();
        using var _ = cert;

        Assert.Throws<ArgumentException>(() => factory.Create(""));
    }

    [Fact]
    public void Null_factory_refuses_a_non_local_endpoint()
    {
        // The development factory must never silently weaken a real deployment.
        var factory = new NullClientAssertionFactory(
            new ServiceIdentityOptions { ClientId = ClientId },
            NullLogger<NullClientAssertionFactory>.Instance);

        var ex = Assert.Throws<InvalidOperationException>(() => factory.Create(TokenEndpoint));
        Assert.Contains("SigningCertificateThumbprint", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Null_factory_allows_a_loopback_endpoint()
    {
        var factory = new NullClientAssertionFactory(
            new ServiceIdentityOptions { ClientId = ClientId },
            NullLogger<NullClientAssertionFactory>.Instance);

        Assert.False(string.IsNullOrEmpty(
            factory.Create("https://localhost:7100/oauth2/apia-as/v1/token")));
    }

    private sealed class StubProvider(X509Certificate2 cert) : ISigningCertificateProvider
    {
        // Returns a copy so the factory's `using` does not dispose the fixture's instance.
        public X509Certificate2 Get() => new(cert.Export(X509ContentType.Pfx));
    }
}
