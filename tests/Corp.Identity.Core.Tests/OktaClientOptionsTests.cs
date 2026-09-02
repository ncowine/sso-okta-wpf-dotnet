using Microsoft.Extensions.Configuration;

namespace Corp.Identity.Core.Tests;

/// <summary>
/// Configuration guards, and the binder behaviour that caused a real defect.
/// </summary>
public class OktaClientOptionsTests
{
    private static OktaClientOptions Valid() => new()
    {
        Domain = "dev-12345678.okta.com",
        ClientId = "0oa1a2b3c4d5e6f7g8h9",
        Scopes = ["openid", "profile", "email", "offline_access"],
        RedirectPorts = [8765, 8766, 8767],
        Resources = new Dictionary<string, ResourceOptions>
        {
            ["ApiA"] = new()
            {
                Name = "ApiA",
                AuthorizationServerId = "aus1a2b3c4d5e6f7g8h9",
                Audience = "api://apia",
                Scopes = ["apia.read"],
                BaseAddress = "https://apia.corp.example/",
            },
        },
    };

    [Fact]
    public void Accepts_a_fully_configured_client() => Valid().Validate();

    [Theory]
    [InlineData("")]
    [InlineData("REPLACE-ME-OKTA-DOMAIN")]
    public void Refuses_to_start_on_an_unconfigured_domain(string domain)
    {
        var options = Valid();
        options.Domain = domain;

        // A placeholder that reaches production is a support call, not a stack trace:
        // fail at startup with a message naming the setting (README Appendix B).
        var ex = Assert.Throws<InvalidOperationException>(options.Validate);
        Assert.Contains("Okta:Domain", ex.Message);
    }

    [Fact]
    public void Refuses_to_start_with_no_scopes()
    {
        var options = Valid();
        options.Scopes = [];

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public void Refuses_to_start_with_no_redirect_ports()
    {
        var options = Valid();
        options.RedirectPorts = [];

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    /// <summary>
    /// The regression test for a defect that would have failed only against a real Okta
    /// tenant: the configuration binder APPENDS to an array that already holds elements
    /// rather than replacing it. With a default of [8765, 8766, 8767] on the property,
    /// AppB's configured [8865, 8866, 8867] bound as all six with AppA's first — so AppB
    /// advertised a redirect URI registered to a different Okta client.
    /// </summary>
    [Fact]
    public void Configured_redirect_ports_replace_rather_than_append_to_the_defaults()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Okta:Domain"] = "dev-12345678.okta.com",
                ["Okta:ClientId"] = "appb-client",
                ["Okta:Scopes:0"] = "openid",
                ["Okta:RedirectPorts:0"] = "8865",
                ["Okta:RedirectPorts:1"] = "8866",
                ["Okta:RedirectPorts:2"] = "8867",
            })
            .Build();

        var options = new OktaClientOptions();
        configuration.GetSection(OktaClientOptions.SectionName).Bind(options);

        Assert.Equal([8865, 8866, 8867], options.RedirectPorts);

        // The first port is the one that ends up in the authorize request when nothing is
        // contending, so getting element 0 right is the whole of it.
        Assert.Equal(8865, options.RedirectPorts[0]);
    }

    [Fact]
    public void Configured_scopes_replace_rather_than_append_to_the_defaults()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Okta:Scopes:0"] = "openid",
                ["Okta:Scopes:1"] = "offline_access",
            })
            .Build();

        var options = new OktaClientOptions();
        configuration.GetSection(OktaClientOptions.SectionName).Bind(options);

        Assert.Equal(["openid", "offline_access"], options.Scopes);
    }

    [Fact]
    public void Issuer_is_built_in_the_shape_an_Okta_custom_authorization_server_uses()
    {
        var resource = Valid().Resources["ApiA"];

        Assert.Equal(
            "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
            resource.IssuerFor("dev-12345678.okta.com"));
    }

    [Fact]
    public void Explains_itself_when_no_resource_is_configured()
    {
        var options = Valid();
        options.Resources = [];

        var ex = Assert.Throws<InvalidOperationException>(() => options.PrimaryResource);
        Assert.Contains("Okta:Resources", ex.Message);
    }
}
