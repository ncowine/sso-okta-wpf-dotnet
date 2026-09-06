using System.IO.Pipes;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Common.Authentication.Callback;

/// <summary>
/// Catches the sign-in response when the redirect URI is a private-use scheme such as
/// <c>myapp://auth/callback</c>.
/// </summary>
/// <remarks>
/// <para>
/// The awkward part of a private-use scheme is that <b>Windows does not hand the response
/// to your running application</b>. It looks the scheme up in the registry and starts a
/// <i>new</i> copy of your executable, passing the callback URI as a command-line
/// argument. The instance that began the sign-in is still sitting there waiting, in a
/// different process, holding the PKCE verifier that the second process does not have.
/// </para>
/// <para>So three things have to happen, and this class owns all three:</para>
/// <list type="number">
/// <item>The scheme is registered with Windows, under HKEY_CURRENT_USER, pointing at this executable.</item>
/// <item>Only one instance runs. A second launch forwards its arguments to the first and exits.</item>
/// <item>The forwarded URI is delivered to whichever sign-in is currently waiting for it.</item>
/// </list>
/// <para>
/// A named pipe carries the URI between processes. The pipe is scoped to the current
/// Windows user, so another user signed in to the same machine cannot read or write it.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class PrivateUriSchemeListener : IRedirectListener
{
    private readonly AuthenticationOptions _options;
    private readonly ILogger _log;
    private readonly string _scheme;
    private readonly string _pipeName;

    /// <summary>
    /// The sign-in currently waiting for a callback, if any. Only one at a time: a second
    /// concurrent sign-in would have no way to tell whose response arrived.
    /// </summary>
    private TaskCompletionSource<string>? _pending;

    private readonly object _pendingLock = new();

    public PrivateUriSchemeListener(AuthenticationOptions options, ILogger log)
    {
        _options = options;
        _log = log;
        _scheme = new Uri(options.RedirectUri).Scheme;

        // Per user, and per scheme. Two different applications on one desktop get two
        // different pipes; the same application for two Windows users gets two as well.
        _pipeName = $"CommonAuth-{_scheme}-{Environment.UserName}";
    }

    public string RedirectUri => _options.RedirectUri;

    /// <summary>
    /// Prepares this process to receive callbacks: registers the scheme if asked to, and
    /// starts listening for forwarded URIs from future launches.
    /// </summary>
    public void Start()
    {
        if (_options.RegisterUriScheme) EnsureSchemeRegistered();

        // Fire and forget by design: the pipe server runs for the life of the process,
        // accepting one forwarded URI at a time.
        _ = Task.Run(ListenForForwardedCallbacksAsync);
    }

    /// <summary>
    /// Waits for the browser to send the user back.
    /// </summary>
    /// <returns>The query string from the callback URI, e.g. <c>?code=…&amp;state=…</c>.</returns>
    public async Task<string> WaitForCallbackAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var pending = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        lock (_pendingLock)
        {
            if (_pending is { Task.IsCompleted: false })
            {
                throw new AuthenticationException(
                    "sign_in_already_in_progress",
                    "A sign-in is already waiting for the browser. Finish or cancel it first.");
            }

            _pending = pending;
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);

        // Cancelling the token completes the promise, so an abandoned sign-in cannot leave
        // this task — or the caller awaiting it — hanging forever.
        await using var registration = deadline.Token.Register(
            () => pending.TrySetCanceled(deadline.Token));

        try
        {
            return await pending.Task.ConfigureAwait(false);
        }
        finally
        {
            lock (_pendingLock)
            {
                if (ReferenceEquals(_pending, pending)) _pending = null;
            }
        }
    }

    /// <summary>
    /// Hands a callback URI to the sign-in that is waiting for it.
    /// </summary>
    /// <remarks>
    /// Called both by the pipe server (for a URI forwarded from a second launch) and by
    /// <see cref="PrivateUriSchemeActivation"/> when this very process was started by the
    /// callback and a sign-in was already pending.
    /// </remarks>
    public bool TryDeliver(string callbackUri)
    {
        if (!Uri.TryCreate(callbackUri, UriKind.Absolute, out var uri)) return false;
        if (!string.Equals(uri.Scheme, _scheme, StringComparison.OrdinalIgnoreCase)) return false;

        TaskCompletionSource<string>? pending;
        lock (_pendingLock) pending = _pending;

        if (pending is null)
        {
            // A callback with nothing waiting for it. Normal if the user clicked a stale
            // link, and not worth alarming anyone about — but do not process it, and do
            // not log the URI, which carries the authorization code.
            _log.LogDebug("Received a {Scheme} callback with no sign-in in progress; ignoring", _scheme);
            return false;
        }

        return pending.TrySetResult(uri.Query);
    }

    // ── Talking between instances ────────────────────────────────────────────

    private async Task ListenForForwardedCallbacksAsync()
    {
        while (true)
        {
            try
            {
                // PipeSecurity is not set: the default gives the creating user full
                // control and grants nothing to anyone else, which is what we want.
                using var server = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.In,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync().ConfigureAwait(false);

                using var reader = new StreamReader(server, Encoding.UTF8);
                var uri = await reader.ReadToEndAsync().ConfigureAwait(false);

                if (!string.IsNullOrWhiteSpace(uri)) TryDeliver(uri.Trim());
            }
            catch (Exception ex)
            {
                // One bad connection must not stop us listening for the next.
                _log.LogWarning(ex, "Failed to read a forwarded callback; continuing to listen");
                await Task.Delay(TimeSpan.FromMilliseconds(250)).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Sends a callback URI to the already-running instance. Called from the short-lived
    /// process that Windows started to deliver it.
    /// </summary>
    /// <remarks>
    /// Retried, because the server handles one connection at a time and there is a brief
    /// gap while it creates the next one. A single sign-in produces two callbacks in quick
    /// succession — the silent attempt fails with <c>login_required</c>, then the
    /// interactive one succeeds — so that gap is not hypothetical.
    /// </remarks>
    internal static bool TryForwardToRunningInstance(string scheme, string callbackUri)
    {
        var pipeName = $"CommonAuth-{scheme}-{Environment.UserName}";

        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.Out);
                client.Connect(timeout: 2000);

                using var writer = new StreamWriter(client, Encoding.UTF8);
                writer.Write(callbackUri);
                writer.Flush();
                return true;
            }
            catch (Exception)
            {
                // Either nobody is listening, or the server is between connections. Give
                // it a moment and try again before concluding the former.
                Thread.Sleep(150);
            }
        }

        return false;
    }

    // ── Registry ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Registers the scheme for the current user, if it is not already pointing here.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything is written under <c>HKEY_CURRENT_USER\Software\Classes</c>: no
    /// elevation, no effect on other users, and removable without an installer.
    /// </para>
    /// <para>
    /// The registration is checked before it is written, so a normal launch does no
    /// registry work at all. That matters: an application that rewrites this key on every
    /// start will quietly fight any other application registered for the same scheme, and
    /// the user gets whichever one launched last.
    /// </para>
    /// </remarks>
    private void EnsureSchemeRegistered()
    {
        try
        {
            var executable = Environment.ProcessPath
                             ?? Assembly.GetEntryAssembly()?.Location;

            if (string.IsNullOrWhiteSpace(executable))
            {
                _log.LogWarning("Could not determine this executable's path; skipping {Scheme} registration", _scheme);
                return;
            }

            var command = $"\"{executable}\" \"%1\"";
            var keyPath = $@"Software\Classes\{_scheme}";

            using (var existing = Registry.CurrentUser.OpenSubKey($@"{keyPath}\shell\open\command"))
            {
                if (existing?.GetValue(null) as string == command)
                {
                    _log.LogDebug("{Scheme} is already registered to this executable", _scheme);
                    return;
                }
            }

            using var key = Registry.CurrentUser.CreateSubKey(keyPath);
            key.SetValue(null, $"URL:{_scheme}");

            // The marker Windows looks for to treat this as a URL protocol at all.
            key.SetValue("URL Protocol", string.Empty);

            using var commandKey = Registry.CurrentUser.CreateSubKey($@"{keyPath}\shell\open\command");
            commandKey.SetValue(null, command);

            _log.LogInformation("Registered the {Scheme} URI scheme for the current user", _scheme);
        }
        catch (Exception ex)
        {
            // Not fatal on its own — the scheme may already be registered by an installer.
            // It becomes visible as a sign-in that never comes back, so say so clearly.
            _log.LogError(ex,
                "Could not register the {Scheme} URI scheme. If it is not registered by " +
                "your installer either, sign-in will open the browser and never return",
                _scheme);
        }
    }
}
