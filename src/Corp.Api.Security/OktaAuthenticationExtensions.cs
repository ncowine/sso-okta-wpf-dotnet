using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Corp.Api.Security;

/// <summary>
/// The security-critical token validation configuration. README §9.2.
/// </summary>
public static class OktaAuthenticationExtensions
{
    public static IServiceCollection AddOktaTokenValidation(
        this IServiceCollection services, OktaApiOptions okta)
    {
        okta.Validate();

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // Discovers issuer metadata and the JWKS from
                // {Authority}/.well-known/openid-configuration. Fetched at first use,
                // cached, and refreshed automatically on key rollover (README §9.4).
                options.Authority = okta.Issuer;
                options.Audience = okta.Audience;

                // Required so the raw token is available for On-Behalf-Of exchange
                // via HttpContext.GetTokenAsync("access_token") (README §9.5).
                options.SaveToken = true;

                // Keep Okta's claim names as they appear on the wire. With the default
                // (true), ASP.NET Core rewrites 'sub' to the long WS-Fed
                // nameidentifier URI and every lookup of "sub" silently returns null.
                // This has been the root cause of real authorization bypasses.
                options.MapInboundClaims = false;

                // The metadata document contains the public keys used to validate every
                // token. Over plaintext HTTP an on-path attacker can substitute their own.
                options.RequireHttpsMetadata = true;

                options.RefreshInterval = TimeSpan.FromHours(6);
                options.AutomaticRefreshInterval = TimeSpan.FromHours(12);

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = okta.Issuer,

                    // Rule 1 (README §3.3). This single setting is what stops a token
                    // minted for another API — or an ID token minted for AppA — being
                    // accepted here. NEVER set it to false.
                    ValidateAudience = true,
                    ValidAudience = okta.Audience,

                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,

                    // Pin the algorithm: blocks 'alg' confusion, 'none', and any attempt
                    // to present a symmetric-keyed token.
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],

                    // The 5-minute default is far too generous when access tokens live
                    // 15 minutes. Requires NTP on the API hosts (README §13.5).
                    ClockSkew = TimeSpan.FromSeconds(30),

                    NameClaimType = "sub",
                    RoleClaimType = "groups",
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        // Log the failure REASON, never the token (README §12.5).
                        var log = context.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("Corp.Api.Security.TokenValidation");

                        log.LogWarning("Token rejected: {Type}: {Message}",
                            context.Exception.GetType().Name, context.Exception.Message);

                        return Task.CompletedTask;
                    },

                    OnChallenge = context =>
                    {
                        // RFC 6750 §3: tell the client WHY, without leaking internals.
                        context.Response.Headers.WWWAuthenticate =
                            $"Bearer realm=\"{okta.Audience}\", error=\"invalid_token\"";
                        return Task.CompletedTask;
                    },
                };
            });

        return services;
    }

    /// <summary>Scope and role policies. README §9.3.</summary>
    public static IServiceCollection AddOktaAuthorization(
        this IServiceCollection services, params string[] scopes)
    {
        services.AddAuthorization(options =>
        {
            foreach (var scope in scopes)
            {
                options.AddPolicy(scope, policy => policy
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context => context.User.HasScope(scope)));
            }

            // A user-initiated endpoint must reject a client-credentials token: a
            // service token carries broader authority than any single user, so serving
            // a user request with one silently escalates every user's privileges
            // (README §7.2).
            options.AddPolicy(PolicyNames.RequiresUser, policy => policy
                .RequireAuthenticatedUser()
                .RequireAssertion(context => !context.User.IsServicePrincipal()));

            options.AddPolicy(PolicyNames.RequiresService, policy => policy
                .RequireAuthenticatedUser()
                .RequireAssertion(context => context.User.IsServicePrincipal()));

            // Deny by default: every endpoint requires an authenticated principal
            // unless it explicitly opts out with [AllowAnonymous]. Without this, a newly
            // added controller with a forgotten [Authorize] is wide open and nothing in
            // the build or the tests tells you (README §9.3).
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
        });

        return services;
    }
}

public static class PolicyNames
{
    public const string RequiresUser = "requires:user";
    public const string RequiresService = "requires:service";
}
