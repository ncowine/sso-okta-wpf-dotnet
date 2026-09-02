using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Api.Security.Delegation;

public interface IClientAssertionFactory
{
    /// <summary>Creates a private_key_jwt assertion addressed to the given token endpoint.</summary>
    string Create(string tokenEndpoint);
}

/// <summary>
/// Supplies the certificate used to sign client assertions. Separated from the factory so
/// the assertion logic is testable without touching the machine certificate store.
/// </summary>
public interface ISigningCertificateProvider
{
    X509Certificate2 Get();
}

/// <summary>Loads the client-auth certificate from <c>LocalMachine\My</c>. README §6.6, §13.3.</summary>
[SupportedOSPlatform("windows")]
public sealed class StoreSigningCertificateProvider(
    ServiceIdentityOptions options,
    ILogger<StoreSigningCertificateProvider> log) : ISigningCertificateProvider
{
    public X509Certificate2 Get()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        var cert = store.Certificates
            .Find(X509FindType.FindByThumbprint, options.SigningCertificateThumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"Client-auth certificate {options.SigningCertificateThumbprint} not found in " +
                "LocalMachine\\My. Check the thumbprint, and check that the app pool identity " +
                "can read the private key — README §13.2 (Load User Profile) and §13.3 (ACL). " +
                "A 'Keyset does not exist' error means the ACL, not the thumbprint.");

        if (!cert.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"Certificate {options.SigningCertificateThumbprint} has no accessible private key. " +
                "Grant the app pool identity read access — README §13.3.");
        }

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

/// <summary>
/// Signs the <c>private_key_jwt</c> that authenticates this API to Okta. README §7.1, §4.4.
/// </summary>
public sealed class X509ClientAssertionFactory(
    ServiceIdentityOptions options,
    ISigningCertificateProvider certificates) : IClientAssertionFactory
{
    /// <summary>Okta caps assertion lifetime; keep it short regardless.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    public string Create(string tokenEndpoint)
    {
        if (string.IsNullOrWhiteSpace(tokenEndpoint))
            throw new ArgumentException("A token endpoint is required.", nameof(tokenEndpoint));

        using var cert = certificates.Get();

        var now = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.ClientId,

            // Okta requires the assertion audience to be the EXACT token endpoint URL.
            // A mismatch is the most common cause of 'invalid_client' (README §14.3).
            Audience = tokenEndpoint,

            Subject = new ClaimsIdentity(
            [
                new Claim("sub", options.ClientId),
                new Claim("jti", Guid.NewGuid().ToString("N")), // replay protection
            ]),

            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.Add(Lifetime).UtcDateTime,
            SigningCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}

/// <summary>
/// Used when no signing certificate is configured — the local DevIdp does not verify
/// client authentication.
/// </summary>
/// <remarks>
/// ⚠️ Development only. It is selected automatically when
/// <c>Okta:Service:SigningCertificateThumbprint</c> is blank, and it throws if anything
/// asks it to authenticate against a non-localhost endpoint, so it cannot silently
/// weaken a real deployment.
/// </remarks>
public sealed class NullClientAssertionFactory(
    ServiceIdentityOptions options,
    ILogger<NullClientAssertionFactory> log) : IClientAssertionFactory
{
    private bool _warned;

    public string Create(string tokenEndpoint)
    {
        if (!IsLocal(tokenEndpoint))
        {
            throw new InvalidOperationException(
                $"No signing certificate is configured, but the token endpoint " +
                $"({tokenEndpoint}) is not local. Set Okta:Service:SigningCertificateThumbprint " +
                "to a certificate registered with your Okta app integration (README §6.6). " +
                "Unauthenticated client assertions are only acceptable against the local DevIdp.");
        }

        if (!_warned)
        {
            _warned = true;
            log.LogWarning(
                "No signing certificate configured; using an unsigned placeholder client " +
                "assertion against {Endpoint}. Development only.", tokenEndpoint);
        }

        return "devidp-no-client-authentication";
    }

    private static bool IsLocal(string endpoint) =>
        Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) &&
        (uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase));
}
