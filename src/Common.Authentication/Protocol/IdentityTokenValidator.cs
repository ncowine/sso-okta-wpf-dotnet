using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Common.Authentication.Protocol;

/// <summary>
/// Checks that an ID token is genuine, current, addressed to us, and produced by the
/// sign-in we just started.
/// </summary>
/// <remarks>
/// <para>
/// It is tempting to skip this. The token arrived over TLS, straight from the provider's
/// token endpoint, in response to a request only we could make — so what is left to check?
/// The answer is that "who signed in" is about to drive everything the application shows
/// and every UI decision it makes, and validation is a few milliseconds against keys we
/// already hold.
/// </para>
/// <para>
/// The signing keys come from the discovery document the client has already fetched and
/// cached, so this costs no extra network call.
/// </para>
/// </remarks>
internal static class IdentityTokenValidator
{
    /// <summary>
    /// How much clock difference to tolerate between this machine and the provider.
    /// </summary>
    /// <remarks>
    /// Five minutes is the usual allowance. A desktop further out than that has a clock
    /// problem that will break far more than sign-in.
    /// </remarks>
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Validates the token and returns the user it describes.
    /// </summary>
    /// <param name="expectedNonce">
    /// The nonce sent with the authorize request. Pass <c>null</c> when refreshing, where
    /// there is no authorize request to bind to.
    /// </param>
    /// <exception cref="AuthenticationException">If any check fails. The message never contains the token.</exception>
    public static async Task<ClaimsPrincipal> ValidateAsync(
        string identityToken,
        OpenIdConnectConfiguration configuration,
        string clientId,
        string? expectedNonce)
    {
        var parameters = new TokenValidationParameters
        {
            // Only this provider may vouch for our users.
            ValidateIssuer = true,
            ValidIssuer = configuration.Issuer,

            // An ID token is addressed to this application. A token minted for a different
            // client — or an access token minted for an API — must not be accepted as
            // proof of who is here.
            ValidateAudience = true,
            ValidAudience = clientId,

            // Only keys the provider currently publishes.
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = configuration.SigningKeys,
            RequireSignedTokens = true,

            // Pin the algorithm rather than trusting what the token claims for itself.
            // Left open, a forged token can name a symmetric algorithm and be "verified"
            // using the provider's public key as if it were a shared secret.
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],

            ValidateLifetime = true,
            ClockSkew = ClockSkew,

            // Keep the claim names as the provider sent them. The default rewrites 'sub'
            // to a long legacy URI, after which every lookup of "sub" quietly returns null.
            NameClaimType = "sub",
            RoleClaimType = "groups",
        };

        var result = await new JsonWebTokenHandler()
            .ValidateTokenAsync(identityToken, parameters)
            .ConfigureAwait(false);

        if (!result.IsValid)
        {
            // The message names the check that failed — audience, signature, lifetime — so
            // it is useful in a log. It never includes the token itself.
            throw new AuthenticationException(
                "invalid_identity_token",
                result.Exception?.Message ?? "The identity token failed validation.");
        }

        if (expectedNonce is not null)
        {
            var token = (JsonWebToken)result.SecurityToken;

            if (!token.TryGetPayloadValue<string>("nonce", out var nonce) ||
                !Pkce.ValuesMatch(nonce, expectedNonce))
            {
                throw new AuthenticationException(
                    "invalid_nonce",
                    "The identity token does not belong to this sign-in request.");
            }
        }

        return new ClaimsPrincipal(result.ClaimsIdentity);
    }

    /// <summary>
    /// Reads an already-validated token to rebuild the user, without re-validating.
    /// </summary>
    /// <remarks>
    /// Used only when restoring a session from a token this library stored itself, having
    /// validated it at the time. Never call this on a token that came from anywhere else.
    /// </remarks>
    public static ClaimsPrincipal ReadStoredToken(string identityToken)
    {
        var token = new JsonWebTokenHandler().ReadJsonWebToken(identityToken);

        var identity = new ClaimsIdentity(
            token.Claims,
            authenticationType: "oidc",
            nameType: "sub",
            roleType: "groups");

        return new ClaimsPrincipal(identity);
    }
}
