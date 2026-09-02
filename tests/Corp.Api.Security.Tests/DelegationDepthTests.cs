using System.Net;
using Corp.Api.Security.Delegation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Corp.Api.Security.Tests;

/// <summary>
/// The delegation cycle guard. README §7.7.
/// </summary>
/// <remarks>
/// ApiA and ApiB call each other, so A→B→A→B is possible and every hop is individually
/// valid. Unguarded it can exhaust the ORG-WIDE Okta /token rate limit, which blocks
/// sign-in for unrelated applications — so this is a blast-radius control, not a nicety.
/// </remarks>
public sealed class DelegationDepthTests
{
    [Fact]
    public async Task Adds_a_depth_header_when_none_is_present()
    {
        var (client, recorder) = CreateClient(inboundDepth: null);

        await client.GetAsync("https://downstream.test/x");

        Assert.Equal("1", recorder.LastRequest!.Headers.GetValues(DelegationDepthHandler.Header).Single());
    }

    [Fact]
    public async Task Increments_an_existing_depth_header()
    {
        var (client, recorder) = CreateClient(inboundDepth: "1");

        await client.GetAsync("https://downstream.test/x");

        Assert.Equal("2", recorder.LastRequest!.Headers.GetValues(DelegationDepthHandler.Header).Single());
    }

    [Fact]
    public async Task Refuses_to_delegate_at_the_maximum_depth()
    {
        var (client, _) = CreateClient(inboundDepth: DelegationDepthHandler.MaxDepth.ToString());

        await Assert.ThrowsAsync<DelegationDepthExceededException>(
            () => client.GetAsync("https://downstream.test/x"));
    }

    [Fact]
    public async Task Refuses_beyond_the_maximum_depth()
    {
        var (client, _) = CreateClient(inboundDepth: "97");

        await Assert.ThrowsAsync<DelegationDepthExceededException>(
            () => client.GetAsync("https://downstream.test/x"));
    }

    [Fact]
    public async Task Treats_a_malformed_depth_header_as_zero()
    {
        // An attacker-supplied header must not be able to disable the guard, but it also
        // must not break a legitimate call.
        var (client, recorder) = CreateClient(inboundDepth: "not-a-number");

        await client.GetAsync("https://downstream.test/x");

        Assert.Equal("1", recorder.LastRequest!.Headers.GetValues(DelegationDepthHandler.Header).Single());
    }

    [Fact]
    public async Task A_full_cycle_terminates()
    {
        // Simulates A -> B -> A -> B …: each hop feeds the previous outbound depth back in
        // as the next inbound depth. It must stop rather than run forever.
        string? depth = null;
        var hops = 0;

        for (; hops < 20; hops++)
        {
            var (client, recorder) = CreateClient(depth);

            try
            {
                await client.GetAsync("https://downstream.test/x");
            }
            catch (DelegationDepthExceededException)
            {
                break;
            }

            depth = recorder.LastRequest!.Headers.GetValues(DelegationDepthHandler.Header).Single();
        }

        Assert.True(hops <= DelegationDepthHandler.MaxDepth,
            $"The cycle ran {hops} hops; the guard should stop it at {DelegationDepthHandler.MaxDepth}.");
    }

    private static (HttpClient Client, RecordingHandler Recorder) CreateClient(string? inboundDepth)
    {
        var context = new DefaultHttpContext();
        if (inboundDepth is not null)
            context.Request.Headers[DelegationDepthHandler.Header] = inboundDepth;

        var accessor = new HttpContextAccessor { HttpContext = context };
        var recorder = new RecordingHandler();

        var handler = new DelegationDepthHandler(accessor, NullLogger<DelegationDepthHandler>.Instance)
        {
            InnerHandler = recorder,
        };

        return (new HttpClient(handler), recorder);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
