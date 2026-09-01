using Corp.Api.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiB.Controllers;

/// <summary>
/// ApiB's business surface. The important thing here is that ApiB enforces its OWN
/// authorization for the user — it does not trust ApiA's judgement about what the user
/// may see. That property is what §7 Pattern 1 buys you (README §7.1).
/// </summary>
[ApiController]
[Route("invoices")]
public sealed class InvoicesController(ILogger<InvoicesController> log) : ControllerBase
{
    /// <summary>
    /// Who ApiB thinks is calling. Compare this against ApiA's /orders/whoami — with
    /// On-Behalf-Of the subject is preserved and 'cid' becomes ApiA's service client;
    /// with client credentials there is no user at all (README §D.5).
    /// </summary>
    [HttpGet("whoami")]
    [Authorize(Policy = "apib.read")]
    public IActionResult WhoAmI()
    {
        var depth = Request.Headers.TryGetValue(
            Corp.Api.Security.Delegation.DelegationDepthHandler.Header, out var raw)
            ? raw.ToString()
            : "0";

        return Ok(new
        {
            api = "ApiB",
            audience = "api://apib",
            subject = User.Subject(),
            oktaUserId = User.OktaUserId(),
            callingClientId = User.CallingClientId(),
            isServicePrincipal = User.IsServicePrincipal(),
            scopes = User.Scopes().ToArray(),
            groups = User.Groups().ToArray(),
            delegationDepth = depth,
        });
    }

    [HttpGet("{id:guid}")]
    [Authorize(Policy = "apib.read")]
    [Authorize(Policy = PolicyNames.RequiresUser)]
    public IActionResult Get(Guid id)
    {
        // ApiB re-derives what this user may see from the token IT received. It does not
        // accept ApiA's word for it. Under Pattern 2 (client credentials) this endpoint
        // is correctly refused, because there is no user whose permissions to check.
        if (!User.Groups().Contains("App-Finance", StringComparer.Ordinal))
        {
            log.LogInformation("Invoice {InvoiceId} denied for {Subject}: not in App-Finance",
                id, User.Subject());

            return Forbid();
        }

        return Ok(new
        {
            invoiceId = id,
            status = "Paid",
            amount = 8_400.00m,
            servedTo = User.Subject(),
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
}
