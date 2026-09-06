using System.Security.Cryptography;
using System.Text;

namespace Common.Authentication.Protocol;

/// <summary>
/// Proof Key for Code Exchange (RFC 7636), plus the two values that tie a sign-in response
/// back to the request that started it.
/// </summary>
/// <remarks>
/// <para>
/// PKCE is what makes a desktop application safe without a client secret. The application
/// invents a random <b>verifier</b>, sends only its SHA-256 hash — the <b>challenge</b> —
/// when it opens the browser, and produces the verifier itself only when redeeming the
/// authorization code over its own TLS connection.
/// </para>
/// <para>
/// So an attacker who intercepts the code has something useless. Redeeming it needs the
/// verifier, which never left this process. That property is what allows a private-use
/// scheme like <c>myapp://</c> — where another installed application could in principle
/// receive the same callback — to be used safely at all.
/// </para>
/// <para>
/// <b>state</b> and <b>nonce</b> do different jobs and you need both. <c>state</c> proves
/// the response belongs to the request we sent, defeating a forged callback.
/// <c>nonce</c> is carried inside the ID token and proves the token was minted for this
/// sign-in, defeating one captured from a different flow and replayed here.
/// </para>
/// </remarks>
internal static class Pkce
{
    /// <summary>
    /// A fresh verifier: 32 random bytes, base64url-encoded to 43 characters.
    /// </summary>
    /// <remarks>
    /// RFC 7636 permits 43 to 128 characters. There is no security benefit beyond 32 bytes
    /// of entropy, and shorter URLs are easier to read when something goes wrong.
    /// </remarks>
    public static string NewVerifier() => Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// The challenge to send to the provider: base64url of SHA-256 over the ASCII bytes of
    /// the verifier.
    /// </summary>
    /// <remarks>
    /// Three details are easy to get wrong and all three are silently fatal — the hash is
    /// over ASCII, the encoding is base64<i>url</i> (so <c>+</c> and <c>/</c> are
    /// substituted), and the padding is stripped. The unit tests pin this against the
    /// worked example in RFC 7636 Appendix B rather than trusting the code to be right.
    /// </remarks>
    public static string Challenge(string verifier) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    /// <summary>A single-use value, compared when the response comes back.</summary>
    public static string NewState() => Base64Url(RandomNumberGenerator.GetBytes(16));

    /// <summary>A single-use value, checked inside the ID token.</summary>
    public static string NewNonce() => Base64Url(RandomNumberGenerator.GetBytes(16));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Compares two short secrets without leaking, through timing, how much of the value
    /// matched.
    /// </summary>
    /// <remarks>
    /// The practical risk here is small — these values are single-use and short-lived —
    /// but constant-time comparison of a secret costs nothing and is the habit worth
    /// having.
    /// </remarks>
    public static bool ValuesMatch(string? actual, string expected)
    {
        if (actual is null || actual.Length != expected.Length) return false;

        var difference = 0;
        for (var i = 0; i < actual.Length; i++) difference |= actual[i] ^ expected[i];
        return difference == 0;
    }
}
