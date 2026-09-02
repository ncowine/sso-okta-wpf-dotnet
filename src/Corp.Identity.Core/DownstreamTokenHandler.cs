using Microsoft.Extensions.Logging;

namespace Corp.Identity;

/// <summary>
/// The CLIENT half of §7 Pattern 3: acquires a second access token addressed to a
/// downstream API and relays it in a distinct header, so the first API can forward it.
/// README §7.3, §8.9.
/// </summary>
/// <remarks>
/// <para>Register it AFTER <see cref="OktaTokenHandler"/>, so the primary token lands in
/// <c>Authorization</c> and this one in <c>X-Downstream-Authorization</c>.</para>
/// <para>⚠️ Use this only when Token Exchange is unavailable on your Okta org. It is
/// weaker than Pattern 1 on four counts, and the second is the one that bites: the
/// desktop — the least trusted machine in the estate — now holds a credential for an API
/// it never calls directly, and the client is coupled to the server's call graph, so a
/// backend refactor becomes a desktop release (README §7.3).</para>
/// </remarks>
public sealed class DownstreamTokenHandler(
    IAuthenticationService auth,
    string downstreamResourceName,
    ILogger<DownstreamTokenHandler> log) : DelegatingHandler
{
    public const string Header = "X-Downstream-Authorization";

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        try
        {
            var token = await auth
                .GetAccessTokenAsync(downstreamResourceName, ct)
                .ConfigureAwait(false);

            request.Headers.Remove(Header);
            request.Headers.TryAddWithoutValidation(Header, $"Bearer {token}");
        }
        catch (Exception ex)
        {
            // Not fatal: many endpoints need no downstream call. Let the API decide,
            // and it will return a clear error if it did need one.
            log.LogWarning(ex,
                "Could not acquire a downstream token for {Resource}; sending the request " +
                "without one. If the endpoint delegates, it will fail with an explanation.",
                downstreamResourceName);
        }

        return await base.SendAsync(request, ct).ConfigureAwait(false);
    }
}
