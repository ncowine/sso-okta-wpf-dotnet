using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Identity.Protocol;

/// <summary>
/// Validates an ID token's signature, issuer, audience, lifetime and nonce against the
/// authorization server's published metadata. README §3.2, §12.2.
/// </summary>
/// <remarks>
/// <para>The signing keys come from the discovery document the client has already fetched
/// and caches, so this costs no extra round trip. On a key rollover the caller refreshes
/// the configuration and retries once — see <see cref="OpenIdConnectClient"/>.</para>
/// <para>The nonce check is the one people leave out. Signature and issuer prove the token
/// is genuine; only the nonce proves it was minted for THIS authorize request rather than
/// captured from another one.</para>
/// </remarks>
internal static class IdentityTokenValidator
{
    /// <summary>
    /// Covers clock drift between the desktop and the authorization server. Five minutes
    /// is the conventional allowance; a machine further out than that has a clock problem
    /// that will break far more than sign-in.
    /// </summary>
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    public static async Task<ClaimsPrincipal> ValidateAsync(
        string identityToken,
        OpenIdConnectConfiguration configuration,
        string clientId,
        string expectedNonce)
    {
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = configuration.Issuer,
            ValidateIssuer = true,

            // An ID token is addressed to this client, never to an API. Accepting one
            // with any other audience is how an access token for a different application
            // gets treated as proof of identity.
            ValidAudience = clientId,
            ValidateAudience = true,

            IssuerSigningKeys = configuration.SigningKeys,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,

            ValidateLifetime = true,
            ClockSkew = ClockSkew,

            // Mirrors the API-side configuration (README §9.2), so the same claim
            // identifies the user on both sides of the wire.
            NameClaimType = "sub",
            RoleClaimType = "groups",
        };

        var result = await new JsonWebTokenHandler()
            .ValidateTokenAsync(identityToken, parameters)
            .ConfigureAwait(false);

        if (!result.IsValid)
        {
            // The message names the failed check — audience, signature, lifetime. The
            // token itself is never included, logged or surfaced (README §D.6).
            throw new IdentityTokenException(
                result.Exception?.Message ?? "The identity token failed validation.");
        }

        var token = (JsonWebToken)result.SecurityToken;

        if (!token.TryGetPayloadValue<string>("nonce", out var nonce) ||
            !CryptographicEquals(nonce, expectedNonce))
        {
            throw new IdentityTokenException(
                "The identity token's nonce does not match the authorize request. The " +
                "response may belong to a different sign-in attempt.");
        }

        return new ClaimsPrincipal(result.ClaimsIdentity);
    }

    /// <summary>Length-independent comparison; these are short, but timing habits matter.</summary>
    private static bool CryptographicEquals(string? a, string b)
    {
        if (a is null || a.Length != b.Length) return false;

        var difference = 0;
        for (var i = 0; i < a.Length; i++) difference |= a[i] ^ b[i];
        return difference == 0;
    }
}

public sealed class IdentityTokenException(string message) : Exception(message);
