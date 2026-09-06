using Common.Authentication;
using Microsoft.Extensions.Configuration;

namespace Common.Authentication.Tests;

/// <summary>
/// Configuration guards. Every one of these is a mistake that would otherwise show up much
/// later, as a sign-in that hangs or an API that returns 401 for no visible reason.
/// </summary>
public class AuthenticationOptionsTests
{
    private static AuthenticationOptions Valid() => new()
    {
        Authority = "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
        ClientId = "0oa1a2b3c4d5e6f7g8h9",
        RedirectUri = "myapp://auth/callback",
        Scopes = ["openid", "profile", "email", "offline_access"],
        Resources = new Dictionary<string, ResourceOptions>
        {
            ["Orders"] = new()
            {
                Name = "Orders",
                Scopes = ["orders.read"],
                BaseAddress = "https://orders.corp.example/",
            },
        },
    };

    [Fact]
    public void Accepts_a_fully_configured_application() => Valid().Validate();

    // ── The redirect URI decides which machinery runs ────────────────────────

    [Theory]
    [InlineData("myapp://auth/callback")]
    [InlineData("com.example.myapp://oauth")]
    [InlineData("MYAPP://AUTH/CALLBACK")]
    public void Recognises_a_private_use_scheme(string redirectUri)
    {
        var options = Valid();
        options.RedirectUri = redirectUri;

        Assert.True(options.UsesPrivateUriScheme);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8765/callback")]
    [InlineData("https://localhost:8765/callback")]
    public void Recognises_a_loopback_redirect(string redirectUri)
    {
        var options = Valid();
        options.RedirectUri = redirectUri;

        // The distinction matters: one registers a scheme with Windows and forwards
        // between processes, the other binds a port. Nobody should have to configure
        // which, so it is read from the URI itself.
        Assert.False(options.UsesPrivateUriScheme);
    }

    // ── Refusing to start on a bad configuration ─────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("https://REPLACE-ME.okta.com/oauth2/REPLACE-ME")]
    public void Refuses_an_unconfigured_authority(string authority)
    {
        var options = Valid();
        options.Authority = authority;

        // A placeholder reaching production should produce a message naming the setting,
        // not a stack trace three screens deep.
        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("Authority", ex.Message);
    }

    [Fact]
    public void Refuses_an_authority_that_is_not_https()
    {
        var options = Valid();
        options.Authority = "http://dev-12345678.okta.com/oauth2/aus1";

        // The metadata at this URL carries the keys every token is validated against.
        // Over plaintext, anyone on the path chooses those keys.
        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("https", ex.Message);
    }

    [Fact]
    public void Refuses_an_unconfigured_client_id()
    {
        var options = Valid();
        options.ClientId = "REPLACE-ME-CLIENT-ID";

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Refuses_a_redirect_uri_that_is_not_absolute()
    {
        var options = Valid();
        options.RedirectUri = "auth/callback";

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Refuses_an_empty_scope_list()
    {
        var options = Valid();
        options.Scopes = [];

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Refuses_scopes_that_omit_openid()
    {
        var options = Valid();
        options.Scopes = ["profile", "email"];

        // Without openid there is no ID token, so there is no statement of who signed in
        // — and the application has nothing to show or to gate on.
        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("openid", ex.Message);
    }

    [Fact]
    public void Refuses_a_resource_with_no_scopes()
    {
        var options = Valid();
        options.Resources["Orders"].Scopes = [];

        // A token minted with no scopes for this API is a token the API will reject, and
        // the failure surfaces at the call site rather than here.
        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    // ── The binder behaviour that has caused a real defect ───────────────────

    /// <summary>
    /// .NET's configuration binder <b>appends</b> to a collection that already holds
    /// items rather than replacing it.
    /// </summary>
    /// <remarks>
    /// This is why <see cref="AuthenticationOptions.Scopes"/> starts empty. Give it a
    /// sensible-looking default and every deployment silently carries those entries in
    /// front of whatever was configured — which, for something like a redirect port list,
    /// means the wrong value ends up first.
    /// </remarks>
    [Fact]
    public void Configured_scopes_replace_the_defaults_rather_than_appending_to_them()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Scopes:0"] = "openid",
                ["Authentication:Scopes:1"] = "offline_access",
            })
            .Build();

        var options = new AuthenticationOptions();
        configuration.GetSection(AuthenticationOptions.SectionName).Bind(options);

        Assert.Equal(["openid", "offline_access"], options.Scopes);
    }

    [Fact]
    public void Binds_a_realistic_configuration_end_to_end()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Authority"] = "https://dev-12345678.okta.com/oauth2/aus1",
                ["Authentication:ClientId"] = "0oa1",
                ["Authentication:RedirectUri"] = "myapp://auth/callback",
                ["Authentication:Scopes:0"] = "openid",
                ["Authentication:Scopes:1"] = "offline_access",
                ["Authentication:Resources:Orders:Scopes:0"] = "orders.read",
                ["Authentication:Resources:Orders:BaseAddress"] = "https://orders.corp.example/",
            })
            .Build();

        var options = new AuthenticationOptions();
        configuration.GetSection(AuthenticationOptions.SectionName).Bind(options);

        options.Validate();

        Assert.True(options.UsesPrivateUriScheme);
        Assert.Equal("orders.read", options.Resources["Orders"].Scopes.Single());
    }
}
