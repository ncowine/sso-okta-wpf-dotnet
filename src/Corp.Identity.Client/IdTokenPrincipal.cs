using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Corp.Identity.Client;

/// <summary>
/// Builds a <see cref="ClaimsPrincipal"/> from an ID token for UI display. README §3.2.
/// </summary>
/// <remarks>
/// <para>This READS an already-verified token; it does not validate one. It is called
/// only for a token OidcClient has just obtained directly from the authorization server
/// over TLS and verified (signature, issuer, nonce). Never call it on a token that
/// arrived from anywhere else.</para>
/// <para>The resulting principal is for rendering the signed-in user and for UI gating
/// only. Every rule enforced from it must be re-enforced server-side (README §8.13).</para>
/// </remarks>
public static class IdTokenPrincipal
{
    public static ClaimsPrincipal From(string idToken)
    {
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(idToken);

        var claims = jwt.Claims.ToList();

        // NameClaimType "sub" mirrors the API-side configuration (README §9.2), so the
        // same claim identifies the user on both sides.
        var identity = new ClaimsIdentity(
            claims,
            authenticationType: "oidc",
            nameType: "sub",
            roleType: "groups");

        return new ClaimsPrincipal(identity);
    }
}
