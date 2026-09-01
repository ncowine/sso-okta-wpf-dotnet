using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Corp.Api.Security;

/// <summary>
/// Reports whether Okta's metadata and signing keys are reachable. README §14.4.
/// </summary>
/// <remarks>
/// Registered as <see cref="HealthStatus.Degraded"/> rather than Unhealthy on purpose:
/// once the JWKS is cached, this API keeps validating already-issued tokens through an
/// Okta outage. Only new sign-ins fail. Failing the health check would remove the API
/// from the load balancer for an outage it can actually survive.
/// </remarks>
public sealed class OktaMetadataHealthCheck(
    IOptionsMonitor<JwtBearerOptions> options) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var jwt = options.Get(JwtBearerDefaults.AuthenticationScheme);

        if (jwt.ConfigurationManager is null)
            return HealthCheckResult.Unhealthy("JwtBearer ConfigurationManager is not configured.");

        try
        {
            var config = await jwt.ConfigurationManager
                .GetConfigurationAsync(cancellationToken)
                .ConfigureAwait(false);

            var keyCount = config.SigningKeys.Count;

            return keyCount > 0
                ? HealthCheckResult.Healthy($"Okta metadata reachable; {keyCount} signing key(s) cached.")
                : HealthCheckResult.Degraded("Okta metadata reachable but no signing keys were returned.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Degraded(
                "Okta metadata unreachable. Cached keys still validate existing tokens; " +
                "new sign-ins will fail. Check egress and TLS interception (README §13.4).",
                ex);
        }
    }
}
