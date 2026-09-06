using System.Net;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Common.Authentication.Callback;

/// <summary>
/// Where the sign-in response comes back to. Two implementations, chosen automatically
/// from the shape of your configured redirect URI.
/// </summary>
internal interface IRedirectListener
{
    /// <summary>The redirect URI to send to the provider. Must match what it has registered.</summary>
    string RedirectUri { get; }

    /// <summary>Called once at startup. Registers a scheme, or binds a port.</summary>
    void Start();

    /// <summary>Waits for the browser to send the user back, and returns the query string.</summary>
    Task<string> WaitForCallbackAsync(TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>
/// Catches the response on <c>http://127.0.0.1:{port}/{path}</c>.
/// </summary>
/// <remarks>
/// <para>
/// The simpler of the two mechanisms, and the one RFC 8252 prefers. There is nothing to
/// register with Windows, no second process, and no way for another application to claim
/// your callback — binding a port is exclusive, and fails loudly if something else holds
/// it.
/// </para>
/// <para>
/// The literal <c>127.0.0.1</c> rather than the name <c>localhost</c> is deliberate: it
/// guarantees we listen on the loopback interface and nothing else. RFC 8252 §8.3 makes
/// the same recommendation.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class LoopbackListener : IRedirectListener
{
    private readonly Uri _redirectUri;
    private readonly ILogger _log;
    private HttpListener? _listener;

    public LoopbackListener(AuthenticationOptions options, ILogger log)
    {
        _redirectUri = new Uri(options.RedirectUri);
        _log = log;
    }

    public string RedirectUri => _redirectUri.ToString().TrimEnd('/');

    public void Start()
    {
        // Nothing to do until a sign-in actually starts: holding the port open between
        // sign-ins would stop a second copy of the app from ever binding it.
    }

    public async Task<string> WaitForCallbackAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var prefix = $"http://127.0.0.1:{_redirectUri.Port}{_redirectUri.AbsolutePath.TrimEnd('/')}/";

        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);

        try
        {
            _listener.Start();
        }
        catch (HttpListenerException ex)
        {
            _listener.Close();
            _listener = null;

            throw new AuthenticationException(
                "redirect_port_unavailable",
                $"Could not listen on {prefix}. Another copy of this application may be " +
                "signing in, or another program is using the port.",
                ex);
        }

        _log.LogInformation("Waiting for the sign-in response on {Prefix}", prefix);

        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(timeout);

            var context = await _listener.GetContextAsync().WaitAsync(deadline.Token).ConfigureAwait(false);
            var query = context.Request.Url?.Query ?? string.Empty;

            await WriteBrowserPageAsync(context.Response).ConfigureAwait(false);
            return query;
        }
        finally
        {
            _listener.Close();
            _listener = null;
        }
    }

    /// <summary>
    /// What the user sees in the browser once they are sent back.
    /// </summary>
    /// <remarks>
    /// It never echoes the query string: that carries the authorization code, and putting
    /// it in the page body would leave it in screenshots and in any proxy that logs
    /// responses. The tab cannot be closed programmatically — a page may only close a
    /// window that script opened — so the page says so instead, and tidies the address
    /// bar.
    /// </remarks>
    private static async Task WriteBrowserPageAsync(HttpListenerResponse response)
    {
        const string html = """
            <!doctype html><html><head><meta charset="utf-8"><title>Signed in</title>
            <style>body{font-family:Segoe UI,system-ui,sans-serif;display:grid;
            place-items:center;height:100vh;margin:0;color:#1a1a1a}
            div{text-align:center}p{color:#666}</style></head>
            <body><div><h1>Signed in</h1>
            <p>You can close this tab and return to the application.</p></div>
            <script>
            try { window.close(); } catch (e) { }
            try { history.replaceState(null, '', location.pathname); } catch (e) { }
            </script></body></html>
            """;

        var bytes = Encoding.UTF8.GetBytes(html);

        response.StatusCode = 200;
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = bytes.Length;

        await response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
        response.OutputStream.Close();
    }
}
