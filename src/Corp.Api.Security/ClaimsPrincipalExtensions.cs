using System.Security.Claims;

namespace Corp.Api.Security;

/// <summary>Claim helpers matching Okta's token shape. README §9.3, §3.4.</summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Okta emits <c>scp</c> as a JSON ARRAY, which .NET surfaces as multiple claims.
    /// Many OAuth guides assume a single space-delimited string, which is what some
    /// other IdPs use. This handles both, so the code survives a provider change.
    /// </summary>
    public static bool HasScope(this ClaimsPrincipal user, string scope) =>
        user.Scopes().Contains(scope, StringComparer.Ordinal);

    public static IEnumerable<string> Scopes(this ClaimsPrincipal user) =>
        user.FindAll("scp")
            .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

    /// <summary>
    /// The immutable Okta user ID. Prefer this over <c>sub</c> as a database key:
    /// an access token's <c>sub</c> is the user's login and changes when their email
    /// does, and it differs from the ID token's <c>sub</c> (README §D.4).
    /// </summary>
    public static string? OktaUserId(this ClaimsPrincipal user) => user.FindFirst("uid")?.Value;

    /// <summary>The client_id that requested this token. Useful in audit logs.</summary>
    public static string? CallingClientId(this ClaimsPrincipal user) => user.FindFirst("cid")?.Value;

    public static string? Subject(this ClaimsPrincipal user) => user.FindFirst("sub")?.Value;

    /// <summary>
    /// True when the token carries no user — a client-credentials token (README §7.2).
    /// A service token is broader authority than any single user's, so it must never be
    /// accepted on an endpoint that serves a user-initiated request.
    /// </summary>
    public static bool IsServicePrincipal(this ClaimsPrincipal user) =>
        user.FindFirst("uid") is null;

    public static IEnumerable<string> Groups(this ClaimsPrincipal user) =>
        user.FindAll("groups").Select(c => c.Value);
}
