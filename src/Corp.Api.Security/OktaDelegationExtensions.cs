using Corp.Api.Security.Delegation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Corp.Api.Security;

public static class OktaDelegationExtensions
{
    /// <summary>Name of the typed client for user-initiated downstream calls.</summary>
    public static string UserClient(string downstreamName) => downstreamName;

    /// <summary>Name of the typed client for background (no user) downstream calls.</summary>
    public static string BackgroundClient(string downstreamName) => $"{downstreamName}:background";

    /// <summary>
    /// Registers the delegation machinery and two named clients for a downstream API.
    /// README §9.5.
    /// </summary>
    /// <remarks>
    /// <para>Two clients are registered deliberately, named so the difference is obvious
    /// at every call site: one carries the USER's identity, one carries the SERVICE's.</para>
    /// <para>The most damaging mistake available in §7 is using the service client to
    /// serve a user request — the downstream API then authorises the service, the user's
    /// own permissions are never checked, and every user silently gains the service's
    /// authority. Two distinct clients make that visible in review rather than buried
    /// inside a handler.</para>
    /// </remarks>
    public static IServiceCollection AddOktaDelegation(
        this IServiceCollection services,
        OktaApiOptions okta,
        string downstreamName,
        DelegationPattern pattern)
    {
        if (!okta.Downstream.TryGetValue(downstreamName, out var downstream))
        {
            throw new InvalidOperationException(
                $"Okta:Downstream:{downstreamName} is not configured (README Appendix B).");
        }

        services.AddHttpContextAccessor();
        services.AddMemoryCache();
        services.AddSingleton(okta);

        var identity = okta.Service
            ?? throw new InvalidOperationException(
                "Okta:Service is not configured. This API needs its own client identity to " +
                "call another API (README §5.3, §6.6).");

        services.AddSingleton(identity);

        // A blank thumbprint selects the development factory, which refuses to be used
        // against anything but a loopback endpoint (README §6.6).
        if (string.IsNullOrWhiteSpace(identity.SigningCertificateThumbprint))
        {
            services.AddSingleton<IClientAssertionFactory, NullClientAssertionFactory>();
        }
        else if (OperatingSystem.IsWindows())
        {
            services.AddSingleton<ISigningCertificateProvider, StoreSigningCertificateProvider>();
            services.AddSingleton<IClientAssertionFactory, X509ClientAssertionFactory>();
        }
        else
        {
            throw new PlatformNotSupportedException(
                "Certificate-based client authentication is implemented against the Windows " +
                "certificate store. Implement ISigningCertificateProvider for other platforms.");
        }

        services.AddHttpClient<IOktaTokenService, OktaTokenService>();
        services.AddTransient<DelegationDepthHandler>();

        // ── User-initiated calls ─────────────────────────────────────────────
        var userClient = services.AddHttpClient(UserClient(downstreamName), client =>
        {
            client.BaseAddress = new Uri(downstream.BaseAddress);
            client.Timeout = TimeSpan.FromSeconds(30);
        });

        switch (pattern)
        {
            case DelegationPattern.OnBehalfOf:
                services.AddTransient(sp => new OnBehalfOfTokenHandler(
                    sp.GetRequiredService<IHttpContextAccessor>(),
                    sp.GetRequiredService<IOktaTokenService>(),
                    downstream,
                    sp.GetRequiredService<ILogger<OnBehalfOfTokenHandler>>()));
                userClient.AddHttpMessageHandler<OnBehalfOfTokenHandler>();
                break;

            case DelegationPattern.ClientRelayed:
                services.AddTransient(sp => new ClientRelayedTokenHandler(
                    sp.GetRequiredService<IHttpContextAccessor>(),
                    sp.GetRequiredService<ILogger<ClientRelayedTokenHandler>>()));
                userClient.AddHttpMessageHandler<ClientRelayedTokenHandler>();
                break;

            default:
                throw new ArgumentOutOfRangeException(
                    nameof(pattern), pattern, "Unknown delegation pattern.");
        }

        // Registered AFTER the token handler so the depth header is applied to the
        // request that actually goes out.
        userClient.AddHttpMessageHandler<DelegationDepthHandler>();

        // ── Background calls: always the service identity (README §7.2) ──────
        services.AddTransient(sp => new ServiceIdentityTokenHandler(
            sp.GetRequiredService<IOktaTokenService>(), downstream));

        services.AddHttpClient(BackgroundClient(downstreamName), client =>
            {
                client.BaseAddress = new Uri(downstream.BaseAddress);
                client.Timeout = TimeSpan.FromSeconds(30);
            })
            .AddHttpMessageHandler<ServiceIdentityTokenHandler>()
            .AddHttpMessageHandler<DelegationDepthHandler>();

        return services;
    }
}
