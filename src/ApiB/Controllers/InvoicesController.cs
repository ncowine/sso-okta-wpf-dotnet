using System.Net.Http.Json;
using Corp.Api.Security;
using Corp.Api.Security.Delegation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiB.Controllers;

/// <summary>
/// ApiB's business surface. The important property here is that ApiB enforces its OWN
/// authorization for the user — it does not trust ApiA's judgement about what the user
/// may see. That is what §7 Pattern 1 buys you (README §7.1).
/// </summary>
[ApiController]
[Route("invoices")]
public sealed class InvoicesController(
    IHttpClientFactory httpClientFactory,
    ILogger<InvoicesController> log) : ControllerBase
{
    /// <summary>
    /// Who ApiB thinks is calling. Compare against ApiA's <c>/orders/whoami</c>: with
    /// On-Behalf-Of the subject is preserved and <c>cid</c> becomes ApiA's service client;
    /// with client credentials there is no user at all (README §D.5).
    /// </summary>
    [HttpGet("whoami")]
    [Authorize(Policy = "apib.read")]
    public IActionResult WhoAmI() => Ok(new
    {
        api = "ApiB",
        audience = "api://apib",
        subject = User.Subject(),
        oktaUserId = User.OktaUserId(),
        callingClientId = User.CallingClientId(),
        isServicePrincipal = User.IsServicePrincipal(),
        scopes = User.Scopes().ToArray(),
        groups = User.Groups().ToArray(),
        delegationDepth = DepthHeader(),
    });

    [HttpGet("{id:guid}")]
    [Authorize(Policy = "apib.read")]
    [Authorize(Policy = PolicyNames.RequiresUser)]
    public IActionResult Get(Guid id)
    {
        // ApiB re-derives what this user may see from the token IT received. Bob is in
        // App-Warehouse only, so this returns 403 for him even though ApiA was happy to
        // make the call — which is the whole point of preserving user identity across
        // the hop rather than letting ApiA vouch for him (README §7.1).
        if (!User.Groups().Contains("App-Finance", StringComparer.Ordinal))
        {
            log.LogInformation("Invoice {InvoiceId} denied for {Subject}: not in App-Finance",
                id, User.Subject());

            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                title = "Not permitted",
                detail = "Invoice access requires membership of App-Finance.",
                subject = User.Subject(),
            });
        }

        return Ok(new
        {
            invoiceId = id,
            status = "Paid",
            amount = 8_400.00m,
            servedTo = User.Subject(),
            servedBy = "ApiB",
        });
    }

    /// <summary>
    /// Aggregate data with no per-user component — safe for a service identity, and
    /// therefore the right shape for a background call (README §7.2).
    /// </summary>
    [HttpGet("summary")]
    [Authorize(Policy = "apib.read")]
    public IActionResult Summary() => Ok(new
    {
        outstanding = 3,
        totalValue = 19_950.00m,
        servedTo = User.IsServicePrincipal() ? $"service:{User.CallingClientId()}" : User.Subject(),
    });

    /// <summary>
    /// The RETURN direction: ApiB calls back into ApiA on the user's behalf.
    /// </summary>
    /// <remarks>
    /// This is the second half of the bidirectional relationship. It needs its own
    /// trusted-server configuration in Okta — trust is directional, so
    /// <c>apib-as</c> trusting <c>apia-as</c> does not imply the reverse (README §5.7).
    /// </remarks>
    [HttpGet("{id:guid}/order-context")]
    [Authorize(Policy = "apib.read")]
    [Authorize(Policy = PolicyNames.RequiresUser)]
    public async Task<IActionResult> OrderContext(Guid id, CancellationToken ct)
    {
        var client = httpClientFactory.CreateClient(OktaDelegationExtensions.UserClient("ApiA"));

        using var response = await client.GetAsync("orders/whoami", ct);

        if (!response.IsSuccessStatusCode)
        {
            log.LogWarning("ApiA returned {Status} for invoice {InvoiceId}",
                (int)response.StatusCode, id);

            return StatusCode(StatusCodes.Status502BadGateway, new
            {
                title = "Downstream call failed",
                downstreamStatus = (int)response.StatusCode,
            });
        }

        return Ok(new
        {
            invoiceId = id,
            calledBackInto = "ApiA",
            depthOnArrival = DepthHeader(),
            apiaSaw = await response.Content.ReadFromJsonAsync<object>(ct),
        });
    }

    /// <summary>
    /// Deliberately drives the ApiA ↔ ApiB cycle so the depth guard can be observed.
    /// </summary>
    /// <remarks>
    /// Every hop here is individually valid — nothing in OAuth stops it. Unguarded this
    /// exhausts resources and can burn the ORG-WIDE Okta /token rate limit, which blocks
    /// sign-in for unrelated applications. <see cref="DelegationDepthHandler"/> stops it
    /// and this endpoint proves it (README §7.7).
    ///
    /// Expect HTTP 508 once depth reaches the limit.
    /// </remarks>
    [HttpGet("cycle-demo")]
    [Authorize(Policy = "apib.read")]
    [Authorize(Policy = PolicyNames.RequiresUser)]
    public async Task<IActionResult> CycleDemo(CancellationToken ct)
    {
        var client = httpClientFactory.CreateClient(OktaDelegationExtensions.UserClient("ApiA"));

        // Ask ApiA to call straight back into ApiB, which will try to call ApiA again…
        using var response = await client.GetAsync("orders/cycle-demo", ct);

        return Ok(new
        {
            note = "If you are reading this, the depth guard has not tripped yet.",
            depthOnArrival = DepthHeader(),
            downstreamStatus = (int)response.StatusCode,
            downstreamBody = await response.Content.ReadAsStringAsync(ct),
        });
    }

    private string DepthHeader() =>
        Request.Headers.TryGetValue(DelegationDepthHandler.Header, out var raw)
            ? raw.ToString()
            : "0";
}
