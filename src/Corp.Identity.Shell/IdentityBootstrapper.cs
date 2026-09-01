using System.Net.Http;
using Corp.Identity.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Prism.Ioc;

namespace Corp.Identity.Shell;

/// <summary>
/// Wires the identity stack into a Prism container. README §8.11.
/// </summary>
/// <remarks>
/// Prism 8 uses its own <see cref="IContainerRegistry"/> rather than
/// <see cref="IServiceCollection"/>, so the Microsoft.Extensions pieces
/// (options, logging, HttpClientFactory) are built into a small side container and the
/// resulting singletons registered into Prism's.
/// </remarks>
public static class IdentityBootstrapper
{
    public static void RegisterIdentity(
        this IContainerRegistry registry,
        IConfiguration configuration,
        string applicationName,
        Func<IUserInteraction> interactionFactory)
    {
        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.AddConfiguration(configuration.GetSection("Logging"));
            logging.AddDebug();
        });

        services.AddOptions<OktaClientOptions>()
            .Bind(configuration.GetSection(OktaClientOptions.SectionName))
            .PostConfigure(options =>
            {
                options.ApplicationName = applicationName;

                // Propagate the dictionary key onto each entry so callers can pass a
                // logical name ("ApiA") rather than an audience URI.
                foreach (var (name, resource) in options.Resources) resource.Name = name;
            });

        services.AddHttpClient();

        var provider = services.BuildServiceProvider();

        registry.RegisterInstance(configuration);
        registry.RegisterInstance(provider.GetRequiredService<ILoggerFactory>());
        registry.RegisterInstance(provider.GetRequiredService<IHttpClientFactory>());
        registry.RegisterInstance(provider.GetRequiredService<IOptions<OktaClientOptions>>());

        registry.RegisterSingleton<ITokenStore, DpapiTokenStore>();
        registry.RegisterSingleton<IAccessTokenCache, AccessTokenCache>();

        registry.RegisterSingleton<IUserInteraction>(_ => interactionFactory());

        registry.RegisterSingleton<IAuthenticationService>(container =>
        {
            var interaction = container.Resolve<IUserInteraction>();

            return new OktaAuthenticationService(
                container.Resolve<IOptions<OktaClientOptions>>(),
                container.Resolve<ITokenStore>(),
                container.Resolve<IAccessTokenCache>(),
                container.Resolve<ILoggerFactory>(),
                container.Resolve<IHttpClientFactory>(),
                focusRestorer: () => interaction.RestoreFocus);
        });

        registry.RegisterSingleton<SessionExpiryNotifier>();
        registry.RegisterSingleton<AuthenticationNavigationGuard>();
    }
}
