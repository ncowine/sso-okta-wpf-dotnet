using System.Runtime.Versioning;
using Corp.Identity.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Corp.Identity;

/// <summary>
/// The single entry point. One call wires the whole identity stack into any
/// <see cref="IServiceCollection"/>. README §8.11.
/// </summary>
/// <remarks>
/// <para>Hosting this in a new WPF application is three lines:</para>
/// <code>
/// services.AddCorpIdentity(configuration, applicationName: "AppA");
/// services.AddCorpApiClient("ApiA");                  // typed HttpClient with tokens attached
/// var auth = provider.GetRequiredService&lt;IAuthenticationService&gt;();
/// </code>
/// <para>Nothing here assumes a UI framework or a DI container beyond the Microsoft
/// abstractions. The host owns logging configuration; this method adds no providers, so
/// it cannot fight whatever sink the application already uses.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class IdentityServiceCollectionExtensions
{
    /// <param name="applicationName">
    /// Names the on-disk token store. One store per application, so two applications on
    /// the same desktop never read each other's refresh tokens (README §4.7).
    /// </param>
    /// <param name="focusRestorer">
    /// Optional. Called after the browser redirect lands, to bring the application window
    /// back to the foreground. WPF hosts pass the one from Corp.Identity.Wpf.
    /// </param>
    public static IServiceCollection AddCorpIdentity(
        this IServiceCollection services,
        IConfiguration configuration,
        string applicationName,
        Func<Action?>? focusRestorer = null)
    {
        services.AddOptions<OktaClientOptions>()
            .Bind(configuration.GetSection(OktaClientOptions.SectionName))
            .PostConfigure(options =>
            {
                options.ApplicationName = applicationName;

                // Propagate the dictionary key onto each entry so callers can pass a
                // logical name ("ApiA") rather than an audience URI.
                foreach (var (name, resource) in options.Resources) resource.Name = name;
            });

        // Named rather than typed: the protocol client needs a plain client with no token
        // handler attached, or acquiring a token would require a token.
        services.AddHttpClient(OpenIdConnectClient.HttpClientName);

        services.AddSingleton<ITokenStore, DpapiTokenStore>();
        services.AddSingleton<IAccessTokenCache, AccessTokenCache>();

        services.AddSingleton<IAuthenticationService>(provider => new OktaAuthenticationService(
            provider.GetRequiredService<IOptions<OktaClientOptions>>(),
            provider.GetRequiredService<ITokenStore>(),
            provider.GetRequiredService<IAccessTokenCache>(),
            provider.GetRequiredService<ILoggerFactory>(),
            provider.GetRequiredService<IHttpClientFactory>(),
            focusRestorer));

        return services;
    }

    /// <summary>
    /// Registers a named <see cref="HttpClient"/> for one configured resource, with the
    /// bearer token attached automatically. README §8.10.
    /// </summary>
    /// <remarks>
    /// <para>The handler chain, outermost first:</para>
    /// <list type="bullet">
    /// <item><see cref="OktaTokenHandler"/> — <c>Authorization: Bearer</c> for this resource,
    /// with a single refresh-and-retry on 401.</item>
    /// <item><see cref="DownstreamTokenHandler"/> — the CLIENT half of §7 Pattern 3, added
    /// only when a second resource is configured. Harmless under Pattern 1: the API simply
    /// ignores the extra header, so both delegation patterns work without a rebuild
    /// (README §7.3, §8.9).</item>
    /// </list>
    /// <para>Consume it as <c>IHttpClientFactory.CreateClient(resourceName)</c>, or add
    /// <c>.AddTypedClient&lt;T&gt;()</c> to the returned builder.</para>
    /// </remarks>
    public static IHttpClientBuilder AddCorpApiClient(
        this IServiceCollection services, string resourceName)
    {
        var builder = services
            .AddHttpClient(resourceName, (provider, http) =>
            {
                var options = provider.GetRequiredService<IOptions<OktaClientOptions>>().Value;

                if (!options.Resources.TryGetValue(resourceName, out var resource))
                {
                    throw new InvalidOperationException(
                        $"Unknown resource '{resourceName}'. Add it under Okta:Resources " +
                        "in appsettings.json (README §8.4).");
                }

                http.BaseAddress = new Uri(resource.BaseAddress);
                http.Timeout = TimeSpan.FromSeconds(30);
            })
            .AddHttpMessageHandler(provider => new OktaTokenHandler(
                provider.GetRequiredService<IAuthenticationService>(),
                resourceName,
                provider.GetRequiredService<ILogger<OktaTokenHandler>>()));

        builder.AddHttpMessageHandler(provider =>
        {
            var options = provider.GetRequiredService<IOptions<OktaClientOptions>>().Value;

            var downstream = options.Resources.Keys
                .FirstOrDefault(name => !string.Equals(name, resourceName, StringComparison.Ordinal));

            return downstream is null
                ? new PassThroughHandler()
                : new DownstreamTokenHandler(
                    provider.GetRequiredService<IAuthenticationService>(),
                    downstream,
                    provider.GetRequiredService<ILogger<DownstreamTokenHandler>>());
        });

        return builder;
    }

    /// <summary>
    /// A handler that does nothing, so the chain can be declared unconditionally and the
    /// decision about whether Pattern 3 applies stays in one place.
    /// </summary>
    private sealed class PassThroughHandler : DelegatingHandler;
}
