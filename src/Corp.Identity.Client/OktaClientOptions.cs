namespace Corp.Identity.Client;

/// <summary>
/// Configuration for a public (desktop) OAuth client. README §8.4.
/// None of this is secret — a public client has no secrets (README §E.3).
/// </summary>
public sealed class OktaClientOptions
{
    public const string SectionName = "Okta";

    /// <summary>e.g. <c>dev-12345678.okta.com</c>, or your Okta custom domain.</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>The Native Application client_id. Public, not a secret.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Used to name the on-disk token store. One store per application.</summary>
    public string ApplicationName { get; set; } = "App";

    /// <summary>Standard OIDC scopes requested on every sign-in.</summary>
    public string[] Scopes { get; set; } = ["openid", "profile", "email", "offline_access"];

    /// <summary>
    /// Loopback ports to try in order. EVERY port here must also be registered as a
    /// redirect URI in Okta (README §4.3, §6.5), or the authorize request is rejected.
    /// </summary>
    public int[] RedirectPorts { get; set; } = [8765, 8766, 8767];

    public string RedirectPath { get; set; } = "/callback";

    public string PostLogoutPath { get; set; } = "/signout-callback";

    /// <summary>
    /// Whether to persist the refresh token across restarts.
    /// MUST be false on shared or kiosk machines — DPAPI CurrentUser gives no
    /// isolation between people sharing one Windows account (README §E.7).
    /// </summary>
    public bool PersistSession { get; set; } = true;

    /// <summary>Logical resource name -> API details. Keyed by e.g. "ApiA".</summary>
    public Dictionary<string, ResourceOptions> Resources { get; set; } = [];

    public ResourceOptions PrimaryResource =>
        Resources.Count > 0
            ? Resources.Values.First()
            : throw new InvalidOperationException(
                "No resources configured. Add at least one entry under Okta:Resources " +
                "in appsettings.json (README §8.4).");

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Domain) || Domain.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Okta:Domain is not configured. Fill in the values from README Appendix B.");

        if (string.IsNullOrWhiteSpace(ClientId) || ClientId.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Okta:ClientId is not configured. Fill in the values from README Appendix B.");

        if (RedirectPorts.Length == 0)
            throw new InvalidOperationException("Okta:RedirectPorts must contain at least one port.");

        foreach (var (name, resource) in Resources)
            resource.Validate(name);
    }
}

public sealed class ResourceOptions
{
    /// <summary>Set from the dictionary key at bind time.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The Custom Authorization Server ID, e.g. <c>aus1a2b3c4d5e6f7g8h9</c>.</summary>
    public string AuthorizationServerId { get; set; } = string.Empty;

    /// <summary>The API's audience, e.g. <c>api://apia</c>.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>API-specific scopes, e.g. <c>apia.read</c>.</summary>
    public string[] Scopes { get; set; } = [];

    public string BaseAddress { get; set; } = string.Empty;

    public string IssuerFor(string domain) => $"https://{domain}/oauth2/{AuthorizationServerId}";

    public void Validate(string name)
    {
        if (string.IsNullOrWhiteSpace(AuthorizationServerId) ||
            AuthorizationServerId.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Okta:Resources:{name}:AuthorizationServerId is not configured (README Appendix B).");
        }

        if (string.IsNullOrWhiteSpace(Audience))
            throw new InvalidOperationException($"Okta:Resources:{name}:Audience is not configured.");
    }
}
