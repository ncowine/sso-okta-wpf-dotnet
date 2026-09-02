using System.Security.Cryptography;
using System.Text;

namespace Corp.Identity.Protocol;

/// <summary>
/// Proof Key for Code Exchange (RFC 7636), plus the <c>state</c> and <c>nonce</c> values
/// that bind an authorize request to its response. README §4.1.
/// </summary>
/// <remarks>
/// <para>PKCE is what makes a public client safe without a secret: the authorization code
/// is useless to anyone who did not generate the verifier. It is mandatory here, never
/// optional — Okta rejects a public-client authorize request without it, and so does the
/// local DevIdp.</para>
/// <para><c>state</c> defends the redirect against cross-site request forgery;
/// <c>nonce</c> binds the ID token to this specific request so a replayed token from a
/// different flow cannot be accepted. Both must be compared on the way back, which is
/// what <see cref="AuthorizeSession"/> exists to enforce.</para>
/// </remarks>
internal static class Pkce
{
    /// <summary>
    /// 32 bytes, base64url-encoded to 43 characters. RFC 7636 allows 43–128; there is no
    /// benefit above 32 bytes of entropy and shorter URLs are easier to debug.
    /// </summary>
    public static string NewVerifier() => Base64Url(RandomNumberGenerator.GetBytes(32));

    public static string Challenge(string verifier) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    /// <summary>Opaque, single-use, and compared on the way back.</summary>
    public static string NewState() => Base64Url(RandomNumberGenerator.GetBytes(16));

    public static string NewNonce() => Base64Url(RandomNumberGenerator.GetBytes(16));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
