using System.Reflection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Api.Security.Tests;

/// <summary>
/// The non-negotiables from README §12.2, enforced as build failures.
/// </summary>
/// <remarks>
/// These rules are worth exactly as much as your ability to stop someone quietly
/// relaxing one at 5pm on a Friday. That is what this file is for (README §15.2).
/// </remarks>
public sealed class ConfigurationGuardTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private JwtBearerOptions Options => factory.Services
        .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
        .Get(JwtBearerDefaults.AuthenticationScheme);

    [Fact]
    public void Audience_validation_is_enabled()
    {
        Assert.True(Options.TokenValidationParameters.ValidateAudience,
            "Disabling audience validation makes EVERY token in the Okta org valid at " +
            "this API — including ID tokens and tokens for other APIs (README §9.2).");
    }

    [Fact]
    public void Issuer_validation_is_enabled_with_an_exact_issuer()
    {
        Assert.True(Options.TokenValidationParameters.ValidateIssuer);
        Assert.False(string.IsNullOrWhiteSpace(Options.TokenValidationParameters.ValidIssuer));
    }

    [Fact]
    public void Signing_key_validation_is_enabled()
    {
        Assert.True(Options.TokenValidationParameters.ValidateIssuerSigningKey);
    }

    [Fact]
    public void Only_rs256_is_accepted()
    {
        var algorithms = Options.TokenValidationParameters.ValidAlgorithms?.ToArray();

        Assert.NotNull(algorithms);
        Assert.Equal([SecurityAlgorithms.RsaSha256], algorithms);
    }

    [Fact]
    public void Lifetime_validation_is_enabled_with_a_tight_clock_skew()
    {
        Assert.True(Options.TokenValidationParameters.ValidateLifetime);

        // The 5-minute default is far too generous for a 15-minute token (README §9.2).
        Assert.True(Options.TokenValidationParameters.ClockSkew <= TimeSpan.FromSeconds(60),
            $"ClockSkew is {Options.TokenValidationParameters.ClockSkew}; expected <= 60s.");
    }

    [Fact]
    public void Inbound_claims_are_not_remapped()
    {
        Assert.False(Options.MapInboundClaims,
            "With MapInboundClaims = true, 'sub' becomes the WS-Fed nameidentifier URI " +
            "and every lookup of \"sub\" silently returns null (README §9.2).");
    }

    [Fact]
    public void The_raw_token_is_saved_for_delegation()
    {
        Assert.True(Options.SaveToken,
            "On-Behalf-Of exchange needs the inbound token via GetTokenAsync (README §9.5).");
    }

    [Fact]
    public void A_deny_by_default_fallback_policy_is_configured()
    {
        var policies = factory.Services.GetRequiredService<IAuthorizationPolicyProvider>();
        var fallback = policies.GetFallbackPolicyAsync().GetAwaiter().GetResult();

        Assert.NotNull(fallback);
    }

    [Fact]
    public void No_delegating_handler_forwards_the_inbound_authorization_header()
    {
        // The §7.5 confused-deputy anti-pattern, caught structurally rather than by
        // code review. ClientRelayedTokenHandler is exempt: it forwards a token the
        // CLIENT minted for the downstream audience, which was never addressed to us.
        var offenders = typeof(OktaApiOptions).Assembly
            .GetTypes()
            .Where(t => typeof(DelegatingHandler).IsAssignableFrom(t) && !t.IsAbstract)
            .Where(t => t.Name != "ClientRelayedTokenHandler")
            .Where(ReadsInboundAuthorizationHeader)
            .Select(t => t.Name)
            .ToArray();

        Assert.True(offenders.Length == 0,
            $"These handlers appear to read the inbound Authorization header and forward " +
            $"it: {string.Join(", ", offenders)}. Forwarding a token outside its audience " +
            $"is the confused-deputy defect (README §7.5).");
    }

    private static bool ReadsInboundAuthorizationHeader(Type handler) =>
        handler.GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            .Any(m => m.Name == "SendAsync" &&
                      m.GetMethodBody() is not null &&
                      HandlerReferencesRequestHeaders(handler));

    private static bool HandlerReferencesRequestHeaders(Type handler) =>
        // Heuristic: a handler that takes IHttpContextAccessor AND is not one of the
        // known-safe token handlers is worth a human look.
        handler.GetConstructors()
            .SelectMany(c => c.GetParameters())
            .Any(p => p.ParameterType.Name == "IHttpContextAccessor")
        && handler.Name is not ("OnBehalfOfTokenHandler" or "DelegationDepthHandler");
}
