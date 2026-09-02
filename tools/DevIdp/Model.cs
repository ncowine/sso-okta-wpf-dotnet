using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace DevIdp;

/// <summary>
/// A local OAuth 2.0 / OIDC authorization server that mimics Okta closely enough to run
/// this solution end to end with no tenant.
/// </summary>
/// <remarks>
/// ⚠️ FOR LOCAL DEVELOPMENT ONLY. It authenticates nobody, validates no credentials, and
/// signs with a key generated at startup. It exists so the flows in README §7 and §10 can
/// be exercised and debugged before an Okta tenant exists — and so the wire format is
/// visible. Never deploy it, never point a production build at it.
///
/// It deliberately reproduces Okta's *shapes*, because those are what break code:
///   - two authorization servers, one per API (README §5.2 Variant B)
///   - 'scp' and 'groups' as JSON ARRAYS, not space-delimited strings (README §3.4)
///   - access-token 'sub' = the user's login; ID-token 'sub' = the user id (README §D.4)
///   - 'uid' and 'cid' claims
///   - rotating refresh tokens (README §5.6)
///   - a session cookie, so the second app signs in silently (README §10.1)
/// </remarks>
public sealed class DevUser
{
    public required string Id { get; init; }          // 00u… -> 'uid', and ID token 'sub'
    public required string Login { get; init; }       // access token 'sub'
    public required string Name { get; init; }
    public required string[] Groups { get; init; }
}

public sealed class AuthServer
{
    public required string Id { get; init; }          // e.g. "apia-as"
    public required string Audience { get; init; }    // e.g. "api://apia"
    public required string[] Scopes { get; init; }

    /// <summary>
    /// Authorization servers permitted to have issued a token-exchange subject token.
    /// Mirrors Okta's trusted-server relationship (README §5.7).
    /// </summary>
    public required string[] TrustedServers { get; init; }

    public string Issuer(string origin) => $"{origin}/oauth2/{Id}";
}

public sealed record PendingCode(
    string ClientId,
    string RedirectUri,
    string CodeChallenge,
    string Scope,
    string UserId,
    string AuthServerId,
    string? Nonce,
    DateTimeOffset Expires);

public sealed record RefreshGrant(
    string ClientId,
    string UserId,
    string Scope,
    string AuthServerId,
    DateTimeOffset Expires);

/// <summary>All state, in memory. Restarting the IdP signs everyone out.</summary>
public sealed class DevIdpStore
{
    public RsaSecurityKey SigningKey { get; } =
        new(RSA.Create(2048)) { KeyId = "devidp-key-1" };

    public ConcurrentDictionary<string, PendingCode> Codes { get; } = new();
    public ConcurrentDictionary<string, RefreshGrant> RefreshTokens { get; } = new();

    /// <summary>Session cookie value -> user id. This is what makes cross-app SSO work.</summary>
    public ConcurrentDictionary<string, string> Sessions { get; } = new();

    public IReadOnlyList<DevUser> Users { get; } =
    [
        new DevUser
        {
            Id = "00udevalice",
            Login = "alice@contoso.com",
            Name = "Alice Chen",
            // In both groups: sees every order, and is allowed at ApiB.
            Groups = ["App-Finance", "App-Warehouse"],
        },
        new DevUser
        {
            Id = "00udevbob",
            Login = "bob@contoso.com",
            Name = "Bob Ndlovu",
            // Warehouse only: ApiB's invoice endpoint returns 403 for Bob, which is the
            // point — it proves ApiB enforces its OWN authorization rather than trusting
            // ApiA's (README §7.1).
            Groups = ["App-Warehouse"],
        },
    ];

    public IReadOnlyDictionary<string, AuthServer> AuthServers { get; } =
        new Dictionary<string, AuthServer>(StringComparer.Ordinal)
        {
            ["apia-as"] = new AuthServer
            {
                Id = "apia-as",
                Audience = "api://apia",
                Scopes = ["apia.read", "apia.write"],
                TrustedServers = ["apib-as"],
            },
            ["apib-as"] = new AuthServer
            {
                Id = "apib-as",
                Audience = "api://apib",
                Scopes = ["apib.read", "apib.write"],
                TrustedServers = ["apia-as"],
            },
        };

    public DevUser? FindUser(string id) =>
        Users.FirstOrDefault(u => u.Id == id || u.Login == id);

    public void Sweep()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var (key, value) in Codes)
            if (value.Expires < now) Codes.TryRemove(key, out _);

        foreach (var (key, value) in RefreshTokens)
            if (value.Expires < now) RefreshTokens.TryRemove(key, out _);
    }

    public static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
