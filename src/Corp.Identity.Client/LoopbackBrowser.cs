using System.Diagnostics;
using System.Net;
using System.Text;
using Duende.IdentityModel.OidcClient.Browser;
using Microsoft.Extensions.Logging;

namespace Corp.Identity.Client;

/// <summary>
/// The bridge between OidcClient and the real system browser. README §8.5.
/// </summary>
/// <remarks>
/// Three responsibilities: bind a loopback port, launch the system browser, capture
/// the redirect. Loopback rather than a custom URI scheme because it needs no registry
/// writes, no installer elevation, and cannot be hijacked by another installed
/// application (README §4.3).
/// </remarks>
public sealed class LoopbackBrowser : IBrowser
{
    private readonly IReadOnlyList<int> _ports;
    private readonly string _path;
    private readonly ILogger _log;
    private readonly Action? _restoreFocus;

    public LoopbackBrowser(
        IReadOnlyList<int> ports,
        string path,
        ILogger log,
        Action? restoreFocus = null)
    {
        _ports = ports;
        _path = path.TrimEnd('/');
        _log = log;
        _restoreFocus = restoreFocus;
    }

    /// <summary>The port actually bound for the most recent flow.</summary>
    public int? BoundPort { get; private set; }

    public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken ct = default)
    {
        using var listener = new HttpListener();

        try
        {
            BoundPort = BindFirstAvailable(listener);
        }
        catch (InvalidOperationException ex)
        {
            _log.LogError(ex, "Could not bind any loopback redirect port");
            return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = ex.Message };
        }

        try
        {
            Process.Start(new ProcessStartInfo(options.StartUrl) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Could not launch the system browser");
            return new BrowserResult
            {
                ResultType = BrowserResultType.UnknownError,
                Error = "No default browser is configured on this machine, or it could not be started.",
            };
        }

        // Bound wait: without this, an abandoned sign-in leaks a listener and a port
        // for the life of the process.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));

        try
        {
            var context = await listener.GetContextAsync().WaitAsync(timeout.Token).ConfigureAwait(false);
            var query = context.Request.Url?.Query ?? string.Empty;

            await WriteBrowserResponseAsync(context.Response).ConfigureAwait(false);

            // Bring the app back to the foreground — otherwise the user is left staring
            // at a browser tab wondering what happened (README §8.12).
            _restoreFocus?.Invoke();

            return new BrowserResult { ResultType = BrowserResultType.Success, Response = query };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new BrowserResult { ResultType = BrowserResultType.UserCancel };
        }
        catch (OperationCanceledException)
        {
            _log.LogWarning("Sign-in timed out after 5 minutes waiting for the browser redirect");
            return new BrowserResult { ResultType = BrowserResultType.Timeout };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Loopback listener failed while awaiting the redirect");
            return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = ex.Message };
        }
    }

    private int BindFirstAvailable(HttpListener listener)
    {
        foreach (var port in _ports)
        {
            try
            {
                listener.Prefixes.Clear();
                listener.Prefixes.Add($"http://127.0.0.1:{port}{_path}/");
                listener.Start();
                _log.LogInformation("Loopback redirect listening on 127.0.0.1:{Port}", port);
                return port;
            }
            catch (HttpListenerException)
            {
                // Port taken — by another instance of this app, or another application.
            }
        }

        throw new InvalidOperationException(
            $"All registered loopback ports ({string.Join(", ", _ports)}) are in use. " +
            "Every port here must also be registered as a redirect URI in Okta (README §6.5). " +
            "If a host firewall blocks loopback binds, sign-in cannot work on this machine.");
    }

    private static async Task WriteBrowserResponseAsync(HttpListenerResponse response)
    {
        // Self-contained: no external CSS, images or fonts. The browser may have no
        // route to your intranet at this moment.
        const string html = """
            <!doctype html><html><head><meta charset="utf-8">
            <title>Signed in</title>
            <style>
              body{font-family:Segoe UI,system-ui,sans-serif;display:grid;
                   place-items:center;height:100vh;margin:0;color:#1a1a1a;background:#fafafa}
              .c{text-align:center}h1{font-size:1.25rem;font-weight:600;margin:0 0 .5rem}
              p{color:#555;font-size:.9rem;margin:0}
            </style></head><body><div class="c">
            <h1>Signed in successfully</h1>
            <p>You can close this tab and return to the application.</p>
            </div><script>setTimeout(function(){window.close();},2000);</script>
            </body></html>
            """;

        var bytes = Encoding.UTF8.GetBytes(html);
        response.StatusCode = 200;
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
        response.Close();
    }
}
