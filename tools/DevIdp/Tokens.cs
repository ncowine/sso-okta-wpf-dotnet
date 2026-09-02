using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace DevIdp;

public static class Tokens
{
    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(90);

    /// <summary>
    /// An access token shaped like Okta's: 'scp' and 'groups' as arrays, 'uid' and 'cid'
    /// present, and 'sub' set to the user's LOGIN rather than their id (README §D.4, §D.5).
    /// </summary>
    public static string AccessToken(
        DevIdpStore store, AuthServer authServer, string origin,
        DevUser? user, string clientId, IEnumerable<string> scopes)
    {
        var now = DateTime.UtcNow;

        var claims = new Dictionary<string, object>
        {
            ["ver"] = 1,
            ["jti"] = $"AT.{Guid.NewGuid():N}",
            ["cid"] = clientId,
            ["scp"] = scopes.ToArray(),
        };

        if (user is not null)
        {
            claims["sub"] = user.Login;
            claims["uid"] = user.Id;
            claims["groups"] = user.Groups;
            claims["auth_time"] = new DateTimeOffset(now).ToUnixTimeSeconds();
        }
        else
        {
            // Client-credentials: no user, so no 'uid'. That absence is how a resource
            // server recognises a service call (README §7.2, §9.3).
            claims["sub"] = clientId;
        }

        return Create(store, authServer.Issuer(origin), authServer.Audience, claims,
                      now, now.Add(AccessTokenLifetime));
    }

    /// <summary>An ID token: audience is the CLIENT, and 'sub' is the user id (README §D.4).</summary>
    public static string IdToken(
        DevIdpStore store, AuthServer authServer, string origin,
        DevUser user, string clientId, string? nonce)
    {
        var now = DateTime.UtcNow;

        var claims = new Dictionary<string, object>
        {
            ["ver"] = 1,
            ["jti"] = $"ID.{Guid.NewGuid():N}",
            ["sub"] = user.Id,
            ["name"] = user.Name,
            ["preferred_username"] = user.Login,
            ["email"] = user.Login,
            ["email_verified"] = true,
            ["groups"] = user.Groups,
            ["amr"] = new[] { "pwd" },
            ["idp"] = "devidp",
            ["auth_time"] = new DateTimeOffset(now).ToUnixTimeSeconds(),
        };

        if (nonce is not null) claims["nonce"] = nonce;

        return Create(store, authServer.Issuer(origin), clientId, claims,
                      now, now.Add(AccessTokenLifetime));
    }

    private static string Create(
        DevIdpStore store, string issuer, string audience,
        Dictionary<string, object> claims, DateTime issuedAt, DateTime expires) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            IssuedAt = issuedAt,
            NotBefore = issuedAt,
            Expires = expires,
            SigningCredentials = new SigningCredentials(store.SigningKey, SecurityAlgorithms.RsaSha256),
        });

    public static JsonWebToken? TryRead(string jwt)
    {
        try { return new JsonWebTokenHandler().ReadJsonWebToken(jwt); }
        catch { return null; }
    }
}
