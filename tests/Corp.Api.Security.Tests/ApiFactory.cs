using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Corp.Api.Security.Tests;

/// <summary>
/// Hosts ApiA in-process with a local signing key. README §15.3.
/// </summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    public TestTokenFactory Tokens { get; } = new();

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureHostConfiguration(config => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Okta:Issuer"] = TestTokenFactory.Issuer,
            ["Okta:Audience"] = TestTokenFactory.Audience,
            ["Okta:Service:ClientId"] = "0oaTESTSERVICE",
            ["Okta:Service:SigningCertificateThumbprint"] = "0000000000000000000000000000000000000000",
            ["Okta:Downstream:ApiB:BaseAddress"] = "https://apib.test.local/",
            ["Okta:Downstream:ApiB:Audience"] = TestTokenFactory.OtherAudience,
            ["Okta:Downstream:ApiB:Scopes"] = "apib.read",
            ["Okta:Downstream:ApiB:Issuer"] = TestTokenFactory.Issuer,
        }));

        builder.ConfigureServices(services =>
        {
            services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                // Override ONLY the key source. ValidateAudience, ValidateIssuer,
                // ValidAlgorithms and ClockSkew all remain exactly as production
                // configures them — relaxing any of them here would mean testing a
                // configuration that never ships (README §15.3).
                options.TokenValidationParameters.IssuerSigningKey = Tokens.SigningKey;
                options.TokenValidationParameters.IssuerSigningKeys = [Tokens.SigningKey];
                options.ConfigurationManager = null!;
                options.Authority = null;
                options.MetadataAddress = null;

                // Acceptable ONLY because there is no metadata endpoint in tests.
                options.RequireHttpsMetadata = false;
            });
        });

        return base.CreateHost(builder);
    }
}
