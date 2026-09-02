using System.Security.Claims;

namespace Corp.Identity;

/// <summary>
/// Everything the rest of the application knows about authentication. README §8.3.
/// </summary>
/// <remarks>
/// Two deliberate constraints:
/// <list type="bullet">
/// <item>There is no <c>AccessToken</c> property. Exposing one invites a view model to
/// grab it once and cache a stale copy. <see cref="GetAccessTokenAsync"/> is the only
/// route, and it is always fresh.</item>
/// <item><c>resourceName</c> is logical ("ApiA"), never a raw audience URI. Audience
/// strings live in configuration, in one place.</item>
/// </list>
/// </remarks>
public interface IAuthenticationService
{
    bool IsAuthenticated { get; }

    /// <summary>
    /// Identity for the UI. Sourced from the ID TOKEN, never the access token (README §3.2).
    /// </summary>
    ClaimsPrincipal? User { get; }

    event EventHandler<AuthenticationStateChangedEventArgs>? StateChanged;

    /// <summary>Interactive sign-in via the system browser.</summary>
    Task<AuthenticationResult> SignInAsync(CancellationToken ct = default);

    /// <summary>Silent restore from a stored refresh token. Call at startup.</summary>
    Task<AuthenticationResult> TryRestoreSessionAsync(CancellationToken ct = default);

    /// <summary>
    /// A valid access token for one resource, refreshing silently when needed.
    /// </summary>
    Task<string> GetAccessTokenAsync(string resourceName, CancellationToken ct = default);

    /// <summary>Drops the cached access token so the next call re-mints it. Used on a 401.</summary>
    void InvalidateAccessToken(string resourceName);

    /// <summary>True when the principal holds the given scope. UI gating only (README §8.13).</summary>
    bool HasScope(string scope);

    /// <summary>How long until the session can no longer be renewed silently.</summary>
    TimeSpan TimeUntilSessionExpiry();

    Task SignOutAsync(SignOutScope scope, CancellationToken ct = default);
}

public enum SignOutScope
{
    /// <summary>
    /// Discard local tokens and revoke the refresh token. The Okta session survives,
    /// so the next launch is silent. Use for account switching, NOT for a "Log out"
    /// menu item (README §11.1).
    /// </summary>
    Local,

    /// <summary>
    /// Also end the Okta session via RP-initiated logout, signing the user out of
    /// every application (README §11.2). This is what "Log out" should do.
    /// </summary>
    Global,
}

public enum AuthenticationChangeReason
{
    SignedIn,
    SessionRestored,
    TokenRefreshed,
    SignedOut,
    SessionExpired,
}

public sealed class AuthenticationStateChangedEventArgs(
    AuthenticationChangeReason reason,
    ClaimsPrincipal? user) : EventArgs
{
    public AuthenticationChangeReason Reason { get; } = reason;
    public ClaimsPrincipal? User { get; } = user;
}

public sealed record AuthenticationResult
{
    public bool Succeeded { get; private init; }
    public ClaimsPrincipal? User { get; private init; }
    public string? Error { get; private init; }
    public string? ErrorDescription { get; private init; }

    public static AuthenticationResult Success(ClaimsPrincipal user) =>
        new() { Succeeded = true, User = user };

    public static AuthenticationResult Failed(string? error, string? description = null) =>
        new() { Succeeded = false, Error = error, ErrorDescription = description };

    /// <summary>No stored session — an interactive sign-in is required. Not an error.</summary>
    public static AuthenticationResult NoSession() =>
        new() { Succeeded = false, Error = "no_session" };
}

public sealed class RefreshFailedException(string oktaError, string? description = null)
    : Exception($"Token refresh failed: {oktaError}. {description}".Trim())
{
    public string OktaError { get; } = oktaError;
}
