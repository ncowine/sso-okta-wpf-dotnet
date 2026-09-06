using System.Security.Claims;

namespace Common.Authentication;

/// <summary>
/// Everything the rest of your application needs to know about signing in.
/// </summary>
/// <remarks>
/// <para>
/// This is the only type your view models should depend on. Inject it, call it,
/// bind to what it reports. Nothing above this interface needs to know that OAuth
/// exists, and nothing above it can reach a raw token by accident.
/// </para>
/// <para>
/// Two deliberate omissions:
/// </para>
/// <list type="bullet">
/// <item>
/// There is no <c>AccessToken</c> property. A property invites a view model to grab
/// the value once and hold a stale copy; <see cref="GetAccessTokenAsync"/> is the only
/// route in, and it is always fresh. In practice you rarely call it at all — the
/// registered <c>HttpClient</c> attaches tokens for you.
/// </item>
/// <item>
/// Resources are named logically ("Orders"), never by audience URI. Audience strings
/// belong in configuration, in exactly one place.
/// </item>
/// </list>
/// </remarks>
public interface IAuthenticationService
{
    /// <summary>True once a user is signed in and we hold a usable session.</summary>
    bool IsSignedIn { get; }

    /// <summary>
    /// Who is signed in, for display and for UI gating. Built from the ID token, which
    /// is the only token that makes a statement about a person.
    /// </summary>
    /// <remarks>
    /// Anything you decide from this principal is a convenience for the user, not a
    /// security control. The API must re-check every rule; a modified client can claim
    /// whatever it likes.
    /// </remarks>
    ClaimsPrincipal? User { get; }

    /// <summary>
    /// Raised whenever the answer to <see cref="IsSignedIn"/> or <see cref="User"/>
    /// changes. Subscribe from your shell view model to keep the UI honest.
    /// </summary>
    /// <remarks>
    /// Raised on a background thread. Marshal to the dispatcher before touching
    /// bindable state.
    /// </remarks>
    event EventHandler<AuthenticationStateChangedEventArgs>? StateChanged;

    /// <summary>
    /// Restores a previous session from the stored refresh token, without showing
    /// anything to the user. Call this at startup, before deciding whether to prompt.
    /// </summary>
    /// <remarks>
    /// A failure here is routine, not exceptional: the refresh token expired, was
    /// rotated out, or an administrator revoked it. It means "ask the user", not
    /// "something is broken".
    /// </remarks>
    Task<AuthenticationResult> RestoreSessionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs the user in, opening their normal browser.
    /// </summary>
    /// <remarks>
    /// Tries silently first. If the browser already holds a session with the identity
    /// provider — because the user signed in to the web dashboard this morning, or to
    /// another application — this completes without showing them anything.
    /// </remarks>
    Task<AuthenticationResult> SignInAsync(CancellationToken cancellationToken = default);

    /// <summary>Gets a valid access token for one configured resource, refreshing if needed.</summary>
    Task<string> GetAccessTokenAsync(string resourceName, CancellationToken cancellationToken = default);

    /// <summary>Drops a cached access token so the next call re-mints it. Used after a 401.</summary>
    void InvalidateAccessToken(string resourceName);

    /// <summary>True when the signed-in user holds the given scope. For UI gating only.</summary>
    bool HasScope(string scope);

    /// <summary>
    /// Signs out. <paramref name="scope"/> decides whether the identity provider's own
    /// session ends too — see <see cref="SignOutScope"/>, because the difference
    /// surprises people.
    /// </summary>
    Task SignOutAsync(SignOutScope scope, CancellationToken cancellationToken = default);
}

/// <summary>How far a sign-out should reach.</summary>
public enum SignOutScope
{
    /// <summary>
    /// Forget this application's tokens and revoke the refresh token. The browser
    /// session survives, so relaunching signs the user straight back in.
    /// <para>Use this for switching accounts. It is NOT what a "Log out" menu item should do.</para>
    /// </summary>
    Application,

    /// <summary>
    /// Also end the session at the identity provider, which signs the user out of every
    /// other application too. This is what "Log out" should mean.
    /// <para>
    /// Warn the user first. "I logged out of one app and it logged me out of all of them"
    /// is reported as a bug roughly every time, even though it is the entire point of
    /// single sign-out.
    /// </para>
    /// </summary>
    Everywhere,
}

/// <summary>Why the authentication state changed.</summary>
public enum AuthenticationChangeReason
{
    SignedIn,
    SessionRestored,
    TokenRefreshed,

    /// <summary>
    /// The session ended on its own — the refresh token expired or was revoked. The user
    /// did not ask for this, so tell them, and offer to sign in again.
    /// </summary>
    SessionExpired,

    SignedOut,
}

public sealed class AuthenticationStateChangedEventArgs(
    AuthenticationChangeReason reason,
    ClaimsPrincipal? user) : EventArgs
{
    public AuthenticationChangeReason Reason { get; } = reason;
    public ClaimsPrincipal? User { get; } = user;

    /// <summary>Convenience for binding: true when a user is signed in after this change.</summary>
    public bool IsSignedIn => User?.Identity?.IsAuthenticated == true;
}

/// <summary>
/// The outcome of a sign-in attempt. Deliberately not an exception: "no session yet" is
/// the normal state of a freshly installed application, not an error to be caught.
/// </summary>
public sealed record AuthenticationResult
{
    public bool Succeeded { get; private init; }
    public ClaimsPrincipal? User { get; private init; }

    /// <summary>The provider's own error code, e.g. <c>login_required</c>. Safe to log.</summary>
    public string? Error { get; private init; }

    /// <summary>A human-readable description, when the provider gave one. Safe to log.</summary>
    public string? ErrorDescription { get; private init; }

    /// <summary>True when the user closed the browser or otherwise backed out.</summary>
    public bool WasCancelled { get; private init; }

    public static AuthenticationResult Success(ClaimsPrincipal user) =>
        new() { Succeeded = true, User = user };

    public static AuthenticationResult Failed(string error, string? description = null) =>
        new() { Succeeded = false, Error = error, ErrorDescription = description };

    public static AuthenticationResult Cancelled() =>
        new() { Succeeded = false, WasCancelled = true, Error = "cancelled" };

    /// <summary>Nothing stored to restore from. Expected on a first run; not a failure.</summary>
    public static AuthenticationResult NoStoredSession() =>
        new() { Succeeded = false, Error = "no_stored_session" };

    /// <summary>A message you can put in front of a user without leaking anything.</summary>
    public string ToDisplayMessage() => this switch
    {
        { Succeeded: true } => "Signed in.",
        { WasCancelled: true } => "Sign-in was cancelled.",
        _ => string.IsNullOrWhiteSpace(ErrorDescription)
            ? $"Sign-in failed ({Error})."
            : $"Sign-in failed: {ErrorDescription}",
    };
}

/// <summary>
/// Thrown when a token could not be obtained and no amount of retrying will help —
/// a misconfiguration, or a provider that refused us.
/// </summary>
/// <remarks>
/// The message never contains a token. It is safe to log and safe to show, though you
/// will usually want to show <see cref="AuthenticationResult.ToDisplayMessage"/> instead.
/// </remarks>
public sealed class AuthenticationException(string error, string? description = null, Exception? inner = null)
    : Exception(description is null ? error : $"{error}: {description}", inner)
{
    public string Error { get; } = error;
    public string? ErrorDescription { get; } = description;

    /// <summary>
    /// True when the provider is telling us the user must interact — they are not signed
    /// in, consent is needed, or an administrator requires re-authentication.
    /// </summary>
    public bool NeedsUserInteraction =>
        Error is "login_required" or "interaction_required"
              or "consent_required" or "account_selection_required";
}
