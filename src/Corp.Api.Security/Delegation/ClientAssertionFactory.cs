using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Api.Security.Delegation;

public interface IClientAssertionFactory
{
    /// <summary>Creates a private_key_jwt assertion for the given token endpoint.</summary>
    string Create(string tokenEndpoint);
}

/// <summary>
/// Signs the <c>private_key_jwt</c> that authenticates this API to Okta. README §7.1, §4.4.
/// </summary>
/// <remarks>
/// A certificate rather than a shared secret because the private key can be generated on
/// the server, marked non-exportable, and never transported at all — and rotation is an
/// overlap of two registered public keys rather than a synchronised secret swap.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class X509ClientAssertionFactory(
    IOptions<OktaApiOptions> options,
    ILogger<X509ClientAssertionFactory> log) : IClientAssertionFactory
{
    private readonly ServiceIdentityOptions _service =
        options.Value.Service
        ?? throw new InvalidOperationException(
            "Okta:Service is not configured. This API needs its own client identity to " +
            "call another API. See README §5.3 and §6.6.");

    public string Create(string tokenEndpoint)
    {
        using var cert = LoadCertificate();

        var now = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _service.ClientId,

            // Okta requires the assertion audience to be the exact token endpoint URL.
            // A mismatch here is the most common cause of 'invalid_client' (README §14.3).
            Audience = tokenEndpoint,

            Subject = new ClaimsIdentity(
            [
                new Claim("sub", _service.ClientId),
                new Claim("jti", Guid.NewGuid().ToString("N")), // replay protection
            ]),

            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.AddMinutes(5).UtcDateTime, // keep short; Okta caps this
            SigningCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private X509Certificate2 LoadCertificate()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        var cert = store.Certificates
            .Find(X509FindType.FindByThumbprint, _service.SigningCertificateThumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"Client-auth certificate {_service.SigningCertificateThumbprint} not found in " +
                "LocalMachine\\My. Check the thumbprint, and check that the app pool identity " +
                "can read the private key — see README §13.2 (Load User Profile) and §13.3 (ACL). " +
                "A 'Keyset does not exist' error means the ACL, not the thumbprint.");

        if (cert.NotAfter < DateTime.Now.AddDays(30))
        {
            log.LogWarning(
                "Okta client-auth certificate expires {NotAfter:u} — rotate now. Register the " +
                "replacement public key in Okta BEFORE removing the old one (README §6.6).",
                cert.NotAfter);
        }

        return cert;
    }
}
