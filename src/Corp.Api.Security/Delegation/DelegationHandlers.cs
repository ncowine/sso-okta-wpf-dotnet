using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Corp.Api.Security.Delegation;

/// <summary>Thrown when an outbound call would exceed the delegation depth limit.</summary>
public sealed class DelegationDepthExceededException(int depth)
    : Exception($"Refusing outbound call at delegation depth {depth}. " +
                "A service call graph this deep indicates a cycle (README §7.7).");

/// <summary>
/// Propagates a hop counter and refuses to delegate past it. README §7.7.
/// </summary>
/// <remarks>
/// ApiA and ApiB call each other, so A→B→A→B is possible and every hop is individually
/// valid — nothing in OAuth stops it. Unguarded it produces resource exhaustion and can
/// exhaust the ORG-WIDE Okta /token rate limit, which prevents unrelated applications
/// and users from signing in. This guard is a blast-radius control, not a nicety.
/// </remarks>
public sealed class DelegationDepthHandler(
    IHttpContextAccessor accessor,
    ILogger<DelegationDepthHandler> log) : DelegatingHandler
{
    public const string Header = "X-Delegation-Depth";
    public const int MaxDepth = 2;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var inbound = 0;
        if (accessor.HttpContext?.Request.Headers.TryGetValue(Header, out var raw) == true)
            _ = int.TryParse(raw.ToString(), out inbound);

        if (inbound >= MaxDepth)
        {
            log.LogError("Delegation depth {Depth} reached calling {Uri} — refusing (README §7.7)",
                inbound, request.RequestUri);
            throw new DelegationDepthExceededException(inbound);
        }

        request.Headers.Remove(Header);
        request.Headers.TryAddWithoutValidation(Header, (inbound + 1).ToString());

        return await base.SendAsync(request, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// §7 Pattern 1 — exchanges the inbound user token for one addressed to the downstream
/// API, preserving the user's identity. README §7.1, §9.5.
/// </summary>
public sealed class OnBehalfOfTokenHandler(
    IHttpContextAccessor accessor,
    IOktaTokenService tokens,
    DownstreamOptions downstream,
    ILogger<OnBehalfOfTokenHandler> log) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var context = accessor.HttpContext
            ?? throw new InvalidOperationException(
                "No HttpContext. On-Behalf-Of requires a user-initiated request; for " +
                "background work use the service-identity client instead (README §7.2).");

        var incoming = await context.GetTokenAsync("access_token").ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "No inbound access token. Ensure JwtBearerOptions.SaveToken = true " +
                "(README §9.5), and that this endpoint requires authentication.");

        var delegated = await tokens.ExchangeOnBehalfOfAsync(
            subjectToken: incoming,
            issuer: downstream.Issuer,
            audience: downstream.Audience,
            scope: downstream.Scopes,
            ct).ConfigureAwait(false);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", delegated);

        log.LogDebug("Calling {Audience} on behalf of {Subject}",
            downstream.Audience, context.User.Subject());

        return await base.SendAsync(request, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// §7 Pattern 2 — this service acting as itself, with no user. README §7.2.
/// </summary>
/// <remarks>
/// A client-credentials token typically carries the union of what every user could do.
/// It must NEVER be used to serve a user-initiated request: the downstream API would
/// authorise the service, the user's own permissions would never be checked, and every
/// user would silently gain the service's authority.
/// </remarks>
public sealed class ServiceIdentityTokenHandler(
    IOktaTokenService tokens,
    DownstreamOptions downstream) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var token = await tokens
            .GetServiceTokenAsync(downstream.Issuer, downstream.Scopes, ct)
            .ConfigureAwait(false);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await base.SendAsync(request, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// §7 Pattern 3 — the desktop client acquired a SECOND access token for the downstream
/// audience and relayed it in a distinct header; this forwards it. README §7.3.
/// </summary>
/// <remarks>
/// <para>Both audience rules still hold: the relayed token was minted for the downstream
/// API, so nothing is forwarded outside its audience. Use it when Token Exchange is
/// unavailable on your Okta org.</para>
/// <para>It is weaker than Pattern 1 on four counts: the desktop holds credentials for
/// an API it never calls; the client is coupled to the server's call graph; the header
/// is a bespoke convention that proxies may drop; and the downstream audit trail loses
/// the acting service.</para>
/// </remarks>
public sealed class ClientRelayedTokenHandler(
    IHttpContextAccessor accessor,
    ILogger<ClientRelayedTokenHandler> log) : DelegatingHandler
{
    public const string Header = "X-Downstream-Authorization";

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var context = accessor.HttpContext
            ?? throw new InvalidOperationException("No HttpContext for a relayed downstream token.");

        if (!context.Request.Headers.TryGetValue(Header, out var relayed) ||
            string.IsNullOrWhiteSpace(relayed.ToString()))
        {
            throw new InvalidOperationException(
                $"Delegation pattern is ClientRelayed but no {Header} header was supplied. " +
                "The desktop client must acquire a second access token for the downstream " +
                "audience and send it (README §7.3, §8.9).");
        }

        var value = relayed.ToString();
        var token = value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? value["Bearer ".Length..]
            : value;

        // NOTE: this token is NOT re-validated here. It was minted for the DOWNSTREAM
        // audience, so this API cannot validate it — only the downstream API can, and
        // it will. Forwarding it is safe precisely because it was never addressed to us.
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        log.LogDebug("Relaying client-supplied downstream token for {Subject}",
            context.User.Subject());

        return await base.SendAsync(request, ct).ConfigureAwait(false);
    }
}
