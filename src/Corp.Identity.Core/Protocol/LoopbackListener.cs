using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Corp.Identity.Protocol;

/// <summary>
/// Binds a loopback port and captures the authorization-code redirect. README §4.3, §8.5.
/// </summary>
/// <remarks>
/// <para>Loopback rather than a custom URI scheme because it needs no registry writes, no
/// installer elevation, and cannot be hijacked: a custom scheme such as <c>appa://</c> is
/// a machine-global namespace that any other installed application can claim, silently
/// intercepting the OAuth callback with no way to detect it.</para>
/// <para>The port is bound BEFORE the authorize URL is built, and
/// <see cref="RedirectUri"/> reports the port actually bound. That ordering is the whole
/// point of the type: build the URL first and a failover to the second port produces an
/// authorize request pointing at a port nothing is listening on, and the sign-in hangs
/// until it times out.</para>
/// <para><c>HttpListener</c> binds a high port on 127.0.0.1 as the interactive user. On
/// Windows that needs no URL ACL, no elevation, and no registration.</para>
/// </remarks>
internal sealed class LoopbackListener : IDisposable
{
    private readonly HttpListener _listener;
    private readonly ILogger _log;
    private bool _disposed;

    /// <param name="ports">
    /// Tried in order. EVERY port here must also be registered as a redirect URI in Okta
    /// (README §6.5), because any of them may end up in the authorize request.
    /// </param>
    public LoopbackListener(IReadOnlyList<int> ports, string path, ILogger log)
    {
        _log = log;
        path = "/" + path.Trim('/');

        foreach (var port in ports)
        {
            // A FRESH listener per attempt. HttpListener disposes itself when Start()
            // fails, so reusing the instance turns the second attempt into an
            // ObjectDisposedException and the failover never happens.
            var candidate = new HttpListener();
            candidate.Prefixes.Add($"http://127.0.0.1:{port}{path}/");

            try
            {
                candidate.Start();
            }
            catch (HttpListenerException)
            {
                // Taken — by another instance of this application, or by anything else.
                candidate.Close();
                continue;
            }

            _listener = candidate;
            Port = port;
            RedirectUri = $"http://127.0.0.1:{port}{path}";
            _log.LogInformation("Loopback redirect listening on {RedirectUri}", RedirectUri);
            return;
        }

        throw new InvalidOperationException(
            $"All registered loopback ports ({string.Join(", ", ports)}) are in use. " +
            "Every port here must also be registered as a redirect URI in Okta (README §6.5). " +
            "If a host firewall blocks loopback binds, sign-in cannot work on this machine.");
    }

    /// <summary>The port actually bound, which may not be the first one requested.</summary>
    public int Port { get; }

    /// <summary>The redirect URI to send to the authorization server. Always matches <see cref="Port"/>.</summary>
    public string RedirectUri { get; } = string.Empty;

    /// <summary>
    /// Waits for the browser redirect and returns its query string.
    /// </summary>
    /// <remarks>
    /// The wait is bounded. Without a timeout an abandoned sign-in leaks a listener and a
    /// port for the life of the process, and the caller's task never completes.
    /// </remarks>
    public async Task<string> WaitForCallbackAsync(TimeSpan timeout, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);

        var context = await _listener.GetContextAsync().WaitAsync(deadline.Token).ConfigureAwait(false);
        var query = context.Request.Url?.Query ?? string.Empty;

        await WriteBrowserResponseAsync(context.Response).ConfigureAwait(false);
        return query;
    }

    /// <summary>
    /// What the user sees in the browser tab once the redirect lands. It must never echo
    /// the query string back: that contains the authorization code (README §D.6).
    /// </summary>
    /// <remarks>
    /// <para>The tab cannot be closed reliably, and that is not a defect here. Per the HTML
    /// standard a context is script-closable only when script opened it, or when its
    /// session history holds a single entry. An authorize flow satisfies neither: the
    /// shell opened the tab, and by now it has walked authorize → sign-in → redirect. The
    /// <c>close()</c> below is therefore best-effort, and expected to no-op.</para>
    /// <para>The address bar is a different matter. It still shows the redirect, code and
    /// all, so the URL is rewritten to drop the query. That does not erase the visit from
    /// the browser's history database — nothing served from here can — but it keeps the
    /// code out of the address bar, out of screenshots, and out of whatever the user does
    /// with the tab next.</para>
    /// </remarks>
    private static async Task WriteBrowserResponseAsync(HttpListenerResponse response)
    {
        const string html = """
            <!doctype html><html><head><meta charset="utf-8"><title>Signed in</title>
            <style>body{font-family:Segoe UI,system-ui,sans-serif;display:grid;
            place-items:center;height:100vh;margin:0;color:#1a1a1a}
            div{text-align:center}p{color:#666}</style></head>
            <body><div><h1>Signed in</h1>
            <p>You can close this tab and return to the application.</p></div>
            <script>
            // Best-effort. Chrome, Edge and Firefox all refuse this for a tab they opened
            // themselves; it costs nothing and succeeds in the rare case one does not.
            try { window.close(); } catch (e) { }

            // Still here, so strip the authorization code from the address bar. This
            // rewrites the current entry in place rather than navigating: sending the tab
            // to about:blank would clear the URL just as well, but would also discard the
            // message above and leave an unexplained blank tab.
            try { history.replaceState(null, '', location.pathname); } catch (e) { }
            </script>
            </body></html>
            """;

        var bytes = Encoding.UTF8.GetBytes(html);

        response.StatusCode = 200;
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = bytes.Length;

        await response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
        response.OutputStream.Close();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try { _listener.Close(); }
        catch (Exception ex) { _log.LogDebug(ex, "Loopback listener close failed"); }
    }
}
