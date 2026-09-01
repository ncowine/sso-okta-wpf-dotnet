using System.Diagnostics;
using Corp.Api.Security;
using Corp.Api.Security.Delegation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

var okta = builder.Configuration.GetSection(OktaApiOptions.SectionName).Get<OktaApiOptions>()
           ?? throw new InvalidOperationException("Missing 'Okta' configuration section.");

// Which §7 pattern this API uses for user-initiated downstream calls.
// Flip it in appsettings.json and observe how the token reaching ApiB changes —
// audience, subject, and the audit trail. See README §7.6 and DEMO.md.
var pattern = builder.Configuration.GetValue("Delegation:Pattern", DelegationPattern.OnBehalfOf);

builder.Services.Configure<OktaApiOptions>(
    builder.Configuration.GetSection(OktaApiOptions.SectionName));

builder.Services.AddOktaTokenValidation(okta);
builder.Services.AddOktaAuthorization("apib.read", "apib.write");
builder.Services.AddOktaDelegation(okta, downstreamName: "ApiA", pattern);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHealthChecks()
    // Okta reachability is DEGRADED, not unhealthy: cached keys mean this API still
    // validates existing tokens during an Okta outage (README §9.4, §14.4). Failing the
    // health check would pull it from the load balancer for an outage it can survive.
    .AddCheck<OktaMetadataHealthCheck>("okta-metadata",
        failureStatus: Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Degraded);

var app = builder.Build();

// Fail fast and loudly at startup if Okta metadata is unreachable, rather than failing
// the first user request several minutes later (README §9.4).
await WarmOktaMetadataAsync(app);

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseExceptionHandler(handler => handler.Run(async context =>
{
    var error = context.Features.Get<IExceptionHandlerFeature>()?.Error;

    var (status, title) = error switch
    {
        DelegationDepthExceededException => (StatusCodes.Status508LoopDetected,
                                             "Delegation cycle detected"),
        OktaTokenException => (StatusCodes.Status502BadGateway,
                               "Downstream authorization failed"),
        InvalidOperationException => (StatusCodes.Status400BadRequest,
                                      "Request could not be delegated"),
        _ => (StatusCodes.Status500InternalServerError, "An unexpected error occurred"),
    };

    // RFC 7807. No stack traces, no token fragments, no Okta error bodies — those go to
    // the log, keyed by traceId (README §9.6, §12.5).
    await Results.Problem(
        title: title,
        statusCode: status,
        extensions: new Dictionary<string, object?>
        {
            ["traceId"] = Activity.Current?.Id ?? context.TraceIdentifier,
        }).ExecuteAsync(context);
}));

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/health").AllowAnonymous();

app.Run();

static async Task WarmOktaMetadataAsync(WebApplication app)
{
    await using var scope = app.Services.CreateAsyncScope();

    var options = scope.ServiceProvider
        .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
        .Get(JwtBearerDefaults.AuthenticationScheme);

    if (options.ConfigurationManager is null)
    {
        // No metadata endpoint: the signing key was supplied directly. This is the
        // test-host configuration (README §15.3) and never a deployed one.
        app.Logger.LogWarning(
            "No Okta metadata endpoint configured; using a directly-supplied signing key. " +
            "This must never happen outside tests.");
        return;
    }

    try
    {
        await options.ConfigurationManager.GetConfigurationAsync(CancellationToken.None);
        app.Logger.LogInformation("Okta metadata loaded from {Authority}", options.Authority);
    }
    catch (Exception ex)
    {
        app.Logger.LogCritical(ex,
            "Cannot reach Okta metadata at {Authority}. Check egress rules and TLS " +
            "interception — see README §13.4.", options.Authority);
        throw;
    }
}

/// <summary>Exposed so WebApplicationFactory can host this API in tests.</summary>
public partial class Program;
