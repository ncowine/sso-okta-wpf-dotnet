using System.Net;
using Corp.Identity.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

namespace Corp.Identity.Core.Tests;

/// <summary>
/// The redirect URI sent to the authorization server must name the port actually bound.
/// </summary>
/// <remarks>
/// This is the regression suite for a real defect: the listener failed over to the next
/// registered port while the authorize request still advertised the first one, so the
/// browser redirected to a dead port and sign-in hung until it timed out. It only
/// reproduced when the first port was already taken, which is exactly the case the
/// failover exists for.
/// </remarks>
public class LoopbackListenerTests
{
    private static readonly int[] Ports = [18765, 18766, 18767];
    private const string Path = "/callback";

    [Fact]
    public void Binds_the_first_port_when_it_is_free()
    {
        using var listener = new LoopbackListener(Ports, Path, NullLogger.Instance);

        Assert.Equal(Ports[0], listener.Port);
        Assert.Equal($"http://127.0.0.1:{Ports[0]}/callback", listener.RedirectUri);
    }

    [Fact]
    public void Falls_over_to_the_next_port_and_the_redirect_uri_follows_it()
    {
        using var occupying = new LoopbackListener(Ports, Path, NullLogger.Instance);
        using var second = new LoopbackListener(Ports, Path, NullLogger.Instance);

        Assert.Equal(Ports[1], second.Port);

        // The assertion that matters: the URI names the port we are listening on, not the
        // first port in the list.
        Assert.Equal($"http://127.0.0.1:{Ports[1]}/callback", second.RedirectUri);
    }

    [Fact]
    public void Explains_itself_when_every_registered_port_is_taken()
    {
        var listeners = Ports.Select(_ => new LoopbackListener(Ports, Path, NullLogger.Instance)).ToList();

        try
        {
            var ex = Assert.Throws<InvalidOperationException>(
                () => new LoopbackListener(Ports, Path, NullLogger.Instance));

            // The message has to name the ports: the operator's next step is to check
            // which of them is registered in Okta.
            Assert.Contains(Ports[0].ToString(), ex.Message);
            Assert.Contains("redirect URI", ex.Message);
        }
        finally
        {
            foreach (var listener in listeners) listener.Dispose();
        }
    }

    [Fact]
    public void Releases_the_port_when_disposed()
    {
        using (var first = new LoopbackListener(Ports, Path, NullLogger.Instance))
        {
            Assert.Equal(Ports[0], first.Port);
        }

        // An abandoned sign-in must not hold a port for the life of the process.
        using var reused = new LoopbackListener(Ports, Path, NullLogger.Instance);
        Assert.Equal(Ports[0], reused.Port);
    }

    [Fact]
    public async Task Callback_response_never_echoes_the_query_string_back()
    {
        using var listener = new LoopbackListener(Ports, Path, NullLogger.Instance);

        var wait = listener.WaitForCallbackAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

        using var http = new HttpClient();
        var page = await http.GetStringAsync($"{listener.RedirectUri}?code=SECRET-CODE&state=abc");

        Assert.Equal("?code=SECRET-CODE&state=abc", await wait);

        // The browser page is rendered from the redirect that carries the authorization
        // code. Reflecting it would leave the code in history, in a screenshot, and in
        // any proxy that logs response bodies (README §D.6).
        Assert.DoesNotContain("SECRET-CODE", page);
    }

    [Fact]
    public async Task Callback_page_tries_to_close_the_tab_and_clears_the_address_bar()
    {
        using var listener = new LoopbackListener(Ports, Path, NullLogger.Instance);

        var wait = listener.WaitForCallbackAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

        using var http = new HttpClient();
        var page = await http.GetStringAsync($"{listener.RedirectUri}?code=SECRET-CODE&state=abc");
        await wait;

        // Closing is expected to fail — the tab is not script-closable — so the URL
        // rewrite is what actually gets the code out of the address bar. Both must be
        // present, and the rewrite must not carry the query along with it.
        Assert.Contains("window.close()", page);
        Assert.Contains("history.replaceState(null, '', location.pathname)", page);

        // The user must still be told what to do when the close attempt no-ops.
        Assert.Contains("close this tab", page);
    }

    [Fact]
    public async Task Waiting_for_a_callback_gives_up_rather_than_hanging_forever()
    {
        using var listener = new LoopbackListener(Ports, Path, NullLogger.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => listener.WaitForCallbackAsync(TimeSpan.FromMilliseconds(200), CancellationToken.None));
    }
}
