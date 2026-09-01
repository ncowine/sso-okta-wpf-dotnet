namespace Corp.Api.Security;

/// <summary>API-side Okta configuration. README §9.1.</summary>
public sealed class OktaApiOptions
{
    public const string SectionName = "Okta";

    /// <summary>
    /// The Custom Authorization Server issuer, e.g.
    /// <c>https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9</c>.
    /// If this has no <c>/oauth2/{id}</c> segment you are pointed at the Org
    /// authorization server, which cannot work here (README §5.1).
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>This API's audience, e.g. <c>api://apia</c>. Rule 1 (README §3.3).</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>Downstream APIs this service calls, keyed by logical name.</summary>
    public Dictionary<string, DownstreamOptions> Downstream { get; set; } = [];

    /// <summary>This API's own client identity, used when it calls another API.</summary>
    public ServiceIdentityOptions? Service { get; set; }

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer) || Issuer.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Okta:Issuer is not configured (README Appendix B).");

        if (string.IsNullOrWhiteSpace(Audience))
            throw new InvalidOperationException("Okta:Audience is not configured (README Appendix B).");

        if (!Issuer.Contains("/oauth2/", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Okta:Issuer '{Issuer}' looks like the Org authorization server. This solution " +
                "requires a Custom Authorization Server — the Org AS cannot issue tokens with " +
                "your own audience or scopes. See README §5.1.");
        }
    }
}

public sealed class DownstreamOptions
{
    public string BaseAddress { get; set; } = string.Empty;

    /// <summary>The downstream API's audience, e.g. <c>api://apib</c>.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>Space-delimited scopes to request for the downstream call.</summary>
    public string Scopes { get; set; } = string.Empty;

    /// <summary>
    /// The authorization server that mints tokens for the downstream audience.
    /// Under Variant B (one AS per API) this differs from this API's own issuer,
    /// and the two must be linked as trusted servers for OBO (README §5.7).
    /// </summary>
    public string Issuer { get; set; } = string.Empty;
}

public sealed class ServiceIdentityOptions
{
    /// <summary>The API Services app integration's client_id.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Thumbprint of the client-auth certificate in LocalMachine\My (README §6.6).</summary>
    public string SigningCertificateThumbprint { get; set; } = string.Empty;
}

/// <summary>Which §7 pattern this API uses for user-initiated downstream calls.</summary>
public enum DelegationPattern
{
    /// <summary>
    /// Pattern 1 — On-Behalf-Of token exchange (RFC 8693). Recommended.
    /// Preserves user identity, satisfies both audience rules, re-evaluates policy
    /// at exchange time. Requires Token Exchange enabled on the org (README §7.1).
    /// </summary>
    OnBehalfOf,

    /// <summary>
    /// Pattern 3 — the client acquired a second token for the downstream audience and
    /// relayed it in a distinct header. Works on any org with no Token Exchange feature,
    /// but couples the desktop client to the server call graph (README §7.3).
    /// </summary>
    ClientRelayed,
}
