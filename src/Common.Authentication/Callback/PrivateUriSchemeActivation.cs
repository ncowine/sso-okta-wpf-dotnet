using System.Runtime.Versioning;

namespace Common.Authentication.Callback;

/// <summary>
/// The single-instance gate. Call this as the very first thing your application does.
/// </summary>
/// <remarks>
/// <para>
/// When a private-use scheme is in play, Windows delivers the sign-in response by starting
/// a <i>second copy</i> of your executable with the callback URI as an argument. That
/// second copy has no PKCE verifier and no waiting user — its only job is to hand the URI
/// to the instance that started the sign-in, and then exit.
/// </para>
/// <para>Use it like this, before anything else in <c>OnStartup</c>:</para>
/// <code>
/// protected override void OnStartup(StartupEventArgs e)
/// {
///     // If this process only exists to deliver a sign-in callback, it hands the URI
///     // to the running instance and we stop here.
///     if (PrivateUriSchemeActivation.ForwardToRunningInstance(e.Args, "myapp"))
///     {
///         Shutdown();
///         return;
///     }
///
///     base.OnStartup(e);
/// }
/// </code>
/// <para>
/// You get single-instance behaviour as a side effect, which is what you want anyway: two
/// copies of the same application would otherwise fight over one token store.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class PrivateUriSchemeActivation
{
    private static Mutex? _instanceLock;

    /// <summary>
    /// If this launch is a callback delivery, forwards it and returns <c>true</c>, meaning
    /// "shut down now". Otherwise claims single-instance ownership and returns <c>false</c>,
    /// meaning "carry on starting up".
    /// </summary>
    /// <param name="args">The command-line arguments handed to your application.</param>
    /// <param name="scheme">Your scheme without the separator — <c>"myapp"</c>, not <c>"myapp://"</c>.</param>
    /// <remarks>
    /// If a callback arrives and no instance is running to receive it — the user clicked a
    /// stale link with the application closed — this returns <c>false</c> and lets the
    /// application start normally. The callback itself is dropped: it belongs to a sign-in
    /// that no longer exists, and its authorization code is single-use and about to expire
    /// anyway.
    /// </remarks>
    public static bool ForwardToRunningInstance(string[] args, string scheme)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);

        var callbackUri = FindCallbackUri(args, scheme);

        // The mutex decides who is the real application, not whether a pipe write
        // happened to succeed. Held for the process lifetime; Windows releases it when
        // the process ends, including when it ends badly.
        _instanceLock = new Mutex(
            initiallyOwned: true,
            $"Local\\CommonAuth-{scheme}-{Environment.UserName}",
            out var isPrimaryInstance);

        if (isPrimaryInstance)
        {
            // Nobody else is running, so we are the application. If we were started by a
            // callback, remember it — though a sign-in that began before this process
            // existed is already gone, so it will simply be ignored.
            PendingActivationUri = callbackUri;
            return false;
        }

        // Another instance owns this application. Whatever else happens, we must not
        // start a second copy of it.
        if (callbackUri is not null)
        {
            PrivateUriSchemeListener.TryForwardToRunningInstance(scheme, callbackUri);
        }

        return true;
    }

    /// <summary>
    /// The callback URI this process was started with, if any. The service reads this on
    /// startup so a sign-in begun before a restart can still complete.
    /// </summary>
    internal static string? PendingActivationUri { get; private set; }

    private static string? FindCallbackUri(string[] args, string scheme)
    {
        var prefix = scheme + "://";
        return args.FirstOrDefault(a => a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

}
