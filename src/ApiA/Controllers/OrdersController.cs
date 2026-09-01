using System.Net.Http.Json;
using Corp.Api.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiA.Controllers;

/// <summary>
/// ApiA's business surface. Demonstrates scope-based authorization (README §9.3) and
/// the ApiA -> ApiB delegated call (README §7).
/// </summary>
[ApiController]
[Route("orders")]
public sealed class OrdersController(
    IHttpClientFactory httpClientFactory,
    ILogger<OrdersController> log) : ControllerBase
{
    private static readonly Order[] Orders =
    [
        new("11111111-1111-1111-1111-111111111111", "Widget assembly", 1_250.00m, "App-Warehouse"),
        new("22222222-2222-2222-2222-222222222222", "Consulting retainer", 8_400.00m, "App-Finance"),
        new("33333333-3333-3333-3333-333333333333", "Freight surcharge", 310.75m, "App-Warehouse"),
    ];

    /// <summary>Who the caller is, as ApiA sees them. The first thing to check in the demo.</summary>
    [HttpGet("whoami")]
    [Authorize(Policy = "apia.read")]
    public IActionResult WhoAmI() => Ok(new
    {
        api = "ApiA",
        audience = "api://apia",
        subject = User.Subject(),
        oktaUserId = User.OktaUserId(),
        callingClientId = User.CallingClientId(),
        isServicePrincipal = User.IsServicePrincipal(),
        scopes = User.Scopes().ToArray(),
        groups = User.Groups().ToArray(),
    });

    [HttpGet]
    [Authorize(Policy = "apia.read")]
    public IActionResult List()
    {
        // Scopes are necessary but never sufficient. 'apia.read' says the TOKEN may read
        // ApiA; it says nothing about which records THIS user may see. Resource-level
        // filtering belongs here, against our own data (README §9.3).
        var visible = Orders
            .Where(order => User.Groups().Contains(order.OwningGroup, StringComparer.Ordinal))
            .ToArray();

        return Ok(visible);
    }

    [HttpPost("{id:guid}/approve")]
    [Authorize(Policy = "apia.write")]
    public IActionResult Approve(Guid id)
    {
        log.LogInformation("Order {OrderId} approved by {Subject}", id, User.Subject());
        return Ok(new { id, approvedBy = User.Subject(), approvedAt = DateTimeOffset.UtcNow });
    }

    /// <summary>
    /// The cross-API call: ApiA fetches billing data from ApiB on the USER's behalf.
    /// </summary>
    /// <remarks>
    /// Requires a real user — a client-credentials token is rejected by the
    /// <see cref="PolicyNames.RequiresUser"/> policy, because serving a user request with
    /// a service identity would mean ApiB authorises the service and never checks this
    /// user's permissions (README §7.2).
    /// </remarks>
    [HttpGet("{id:guid}/billing")]
    [Authorize(Policy = "apia.read")]
    [Authorize(Policy = PolicyNames.RequiresUser)]
    public async Task<IActionResult> Billing(Guid id, CancellationToken ct)
    {
        var client = httpClientFactory.CreateClient(OktaDelegationExtensions.UserClient("ApiB"));

        using var response = await client.GetAsync($"invoices/{id}", ct);

        if (!response.IsSuccessStatusCode)
        {
            log.LogWarning("ApiB returned {Status} for order {OrderId}", (int)response.StatusCode, id);
            return StatusCode(StatusCodes.Status502BadGateway, new
            {
                title = "Downstream call failed",
                downstreamStatus = (int)response.StatusCode,
            });
        }

        var invoice = await response.Content.ReadFromJsonAsync<object>(ct);
        return Ok(new { orderId = id, invoice });
    }

    /// <summary>
    /// A background-style call using ApiA's OWN identity, with no user involved.
    /// The token ApiB receives has a 'cid' and no 'uid' (README §7.2, §D.5).
    /// </summary>
    [HttpGet("reconcile")]
    [Authorize(Policy = "apia.read")]
    public async Task<IActionResult> Reconcile(CancellationToken ct)
    {
        var client = httpClientFactory.CreateClient(OktaDelegationExtensions.BackgroundClient("ApiB"));

        using var response = await client.GetAsync("invoices/summary", ct);
        var summary = await response.Content.ReadAsStringAsync(ct);

        return Ok(new { calledAs = "service identity", downstream = summary });
    }
}

public sealed record Order(string Id, string Description, decimal Amount, string OwningGroup);
