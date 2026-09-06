namespace Common.Authentication;

/// <summary>
/// Everything the library needs to know, bound from your <c>appsettings.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// None of this is secret. A desktop application is a "public client": it cannot keep a
/// secret, because anything compiled into it can be read out of the binary. That is not a
/// weakness in this design — it is why PKCE exists, and why there is no client secret
/// anywhere in this library.
/// </para>
/// <para>Example:</para>
/// <code>
/// "Authentication": {
///   "Authority":   "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
///   "ClientId":    "0oa1a2b3c4d5e6f7g8h9",
///   "RedirectUri": "myapp://auth/callback",
///   "Scopes":      [ "openid", "profile", "email", "offline_access" ],
///   "Resources": {
///     "Orders": { "Scopes": [ "orders.read" ], "BaseAddress": "https://orders.corp.example/" }
///   }
/// }
/// </code>
/// </remarks>
public sealed class AuthenticationOptions
{
    /// <summary>The configuration section this binds from.</summary>
    public const string SectionName = "Authentication";

    /// <summary>
    /// The full issuer URL of your authorization server, including the server id.
    /// <para>
    /// For an Okta custom authorization server that is
    /// <c>https://{yourOrg}.okta.com/oauth2/{authServerId}</c> — not the bare org URL.
    /// Getting this wrong produces an <c>invalid issuer</c> rejection at the API, which
    /// reads as a code bug and is really a configuration one.
    /// </para>
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>The application's client id. Public, not a secret.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Where the provider sends the user back, exactly as registered with it.
    /// </summary>
    /// <remarks>
    /// <para>Two shapes work, and the library picks its behaviour from which one you use:</para>
    /// <list type="bullet">
    /// <item>
    /// <b>A private-use scheme</b> — <c>myapp://auth/callback</c>. Windows launches a new
    /// copy of your application to deliver the response, so the library registers the
    /// scheme, keeps a single instance, and forwards the callback to the running one.
    /// </item>
    /// <item>
    /// <b>A loopback address</b> — <c>http://127.0.0.1:8765/callback</c>. The library binds
    /// the port and catches the redirect directly. Nothing is registered with Windows.
    /// </item>
    /// </list>
    /// <para>
    /// Loopback is the option RFC 8252 prefers, because a private-use scheme is a
    /// machine-wide namespace that any other installed application can also claim. If your
    /// provider is already configured for a private-use scheme, use it — PKCE and
    /// <c>state</c> are what make it safe, and both are always on here.
    /// </para>
    /// </remarks>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>Where the provider returns after a sign-out. Defaults to <see cref="RedirectUri"/>.</summary>
    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Scopes requested on every sign-in.
    /// </summary>
    /// <remarks>
    /// <c>offline_access</c> is what earns you a refresh token. Without it the user is
    /// asked to sign in again the moment the first access token expires, which with a
    /// typical 15-minute lifetime is a support call before lunch.
    /// <para>
    /// Deliberately empty by default: .NET's configuration binder <i>appends</i> to a
    /// non-empty collection rather than replacing it, so a default here would survive
    /// into your configuration as entries nobody asked for.
    /// </para>
    /// </remarks>
    public string[] Scopes { get; set; } = [];

    /// <summary>
    /// The APIs this application calls, keyed by a name you choose. The key is what you
    /// pass to <c>GetAccessTokenAsync</c> and what names the registered <c>HttpClient</c>.
    /// </summary>
    public Dictionary<string, ResourceOptions> Resources { get; set; } = [];

    /// <summary>
    /// Whether to keep the refresh token between runs, so the user is not asked to sign in
    /// every morning.
    /// </summary>
    /// <remarks>
    /// Set this false on shared or kiosk machines. Storage is DPAPI under the current
    /// Windows user, which gives no isolation at all between people sharing one Windows
    /// account.
    /// </remarks>
    public bool PersistSession { get; set; } = true;

    /// <summary>
    /// Register the private-use scheme with Windows on startup, if it is not already
    /// registered to this executable.
    /// </summary>
    /// <remarks>
    /// Writes to <c>HKEY_CURRENT_USER</c> only, so it needs no elevation and affects only
    /// the signed-in user. Set this false if your installer does the registration instead
    /// — which is tidier, because an application that re-registers on every launch will
    /// silently fight any other application claiming the same scheme.
    /// <para>Ignored entirely when <see cref="RedirectUri"/> is a loopback address.</para>
    /// </remarks>
    public bool RegisterUriScheme { get; set; } = true;

    /// <summary>
    /// How long to wait for the user to finish in the browser before giving up.
    /// </summary>
    /// <remarks>
    /// Long enough for a password plus an MFA prompt; short enough that an abandoned
    /// attempt does not leave a promise dangling for the life of the process.
    /// </remarks>
    public TimeSpan SignInTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Names the on-disk token store, so two applications on one desktop never read each
    /// other's tokens. Defaults to the entry assembly name.
    /// </summary>
    public string? ApplicationName { get; set; }

    /// <summary>True when <see cref="RedirectUri"/> is a private-use scheme such as <c>myapp://</c>.</summary>
    public bool UsesPrivateUriScheme =>
        Uri.TryCreate(RedirectUri, UriKind.Absolute, out var uri) &&
        uri.Scheme is not ("http" or "https");

    /// <summary>
    /// Fails loudly at startup rather than mysteriously on first use.
    /// </summary>
    /// <remarks>
    /// Every message names the setting that is wrong. A placeholder that reaches
    /// production should produce a support call someone can act on, not a stack trace.
    /// </remarks>
    public void Validate()
    {
        Require(Authority, $"{SectionName}:Authority");
        Require(ClientId, $"{SectionName}:ClientId");
        Require(RedirectUri, $"{SectionName}:RedirectUri");

        if (!Uri.TryCreate(Authority, UriKind.Absolute, out var authority) || authority.Scheme != "https")
        {
            throw new InvalidOperationException(
                $"{SectionName}:Authority must be an absolute https URL. The metadata it " +
                "returns contains the keys used to validate every token, so it cannot be " +
                "fetched over plaintext.");
        }

        if (!Uri.TryCreate(RedirectUri, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException(
                $"{SectionName}:RedirectUri must be an absolute URI, e.g. " +
                "'myapp://auth/callback' or 'http://127.0.0.1:8765/callback'.");
        }

        if (Scopes.Length == 0)
        {
            throw new InvalidOperationException(
                $"{SectionName}:Scopes must list the scopes to request. Start with " +
                "openid, profile, email and offline_access.");
        }

        if (!Scopes.Contains("openid", StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"{SectionName}:Scopes must include 'openid'. Without it the provider " +
                "returns no ID token, and there is no statement of who signed in.");
        }

        foreach (var (name, resource) in Resources) resource.Validate(name);
    }

    private static void Require(string value, string setting)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{setting} is not configured.");
        }
    }
}

/// <summary>One API this application calls.</summary>
public sealed class ResourceOptions
{
    /// <summary>Set from the dictionary key when configuration binds. You do not set this.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The scopes this API needs, on top of the shared ones.</summary>
    public string[] Scopes { get; set; } = [];

    /// <summary>The API's base address, used for the registered <c>HttpClient</c>.</summary>
    public string BaseAddress { get; set; } = string.Empty;

    public void Validate(string name)
    {
        if (Scopes.Length == 0)
        {
            throw new InvalidOperationException(
                $"{AuthenticationOptions.SectionName}:Resources:{name}:Scopes is empty. " +
                "A resource with no scopes yields a token the API will reject.");
        }

        if (!string.IsNullOrWhiteSpace(BaseAddress) &&
            !Uri.TryCreate(BaseAddress, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException(
                $"{AuthenticationOptions.SectionName}:Resources:{name}:BaseAddress " +
                "must be an absolute URL.");
        }
    }
}
