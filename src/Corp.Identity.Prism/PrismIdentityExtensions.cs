using System.Net.Http;
using System.Runtime.Versioning;
using Corp.Identity.Wpf;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Prism.Ioc;

namespace Corp.Identity.Prism;

/// <summary>
/// Bridges the identity stack into a Prism container. README §8.11.
/// </summary>
/// <remarks>
/// <para>Prism 8 uses its own <see cref="IContainerRegistry"/> rather than
/// <see cref="IServiceCollection"/>, so the stack is composed in a standard Microsoft
/// service collection — exactly as a non-Prism host would compose it — and the resulting
/// singletons are then handed to Prism. That keeps
/// <c>AddCorpIdentity</c> the single definition of what the stack contains.</para>
/// <para>This is the only assembly in the identity stack with a third-party dependency.
/// A WPF application that does not use Prism never references it.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class PrismIdentityExtensions
{
    /// <param name="busyHost">
    /// Resolved lazily. The shell view model takes <see cref="IUserInteraction"/> in its
    /// own constructor, so it does not exist when this runs.
    /// </param>
    /// <param name="resourceNames">
    /// Logical resource names to register typed HTTP clients for, e.g. <c>"ApiA"</c>.
    /// </param>
    public static IContainerRegistry RegisterIdentity(
        this IContainerRegistry registry,
        IConfiguration configuration,
        string applicationName,
        Func<IBusyHost?> busyHost,
        params string[] resourceNames)
    {
        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.AddConfiguration(configuration.GetSection("Logging"));
            logging.AddDebug();

            // A WinExe has no console of its own, so this is silent under a normal
            // launch. It produces output only when stdout is redirected —
            // `dotnet run --project src/AppA > appa.log` — which is how the sign-in flow
            // is meant to be read (DEMO.md).
            logging.AddSimpleConsole(o => o.SingleLine = true);
        });

        services.AddCorpIdentity(configuration, applicationName, WpfIdentityExtensions.FocusRestorer);
        services.AddCorpIdentityWpf(busyHost);

        foreach (var resourceName in resourceNames)
            services.AddCorpApiClient(resourceName);

        var provider = services.BuildServiceProvider();

        registry.RegisterInstance(configuration);
        registry.RegisterInstance(provider.GetRequiredService<ILoggerFactory>());
        registry.RegisterInstance(provider.GetRequiredService<IHttpClientFactory>());
        registry.RegisterInstance(provider.GetRequiredService<IOptions<OktaClientOptions>>());
        registry.RegisterInstance(provider.GetRequiredService<IAuthenticationService>());
        registry.RegisterInstance(provider.GetRequiredService<IUserInteraction>());
        registry.RegisterInstance(provider.GetRequiredService<SessionExpiryNotifier>());

        // Prism's container is not the Microsoft one, so AddLogging's open generic
        // ILogger<T> does not cross over — only ILoggerFactory does. Without this,
        // anything taking an ILogger<T> in its constructor fails to resolve at startup.
        registry.Register(typeof(ILogger<>), typeof(Logger<>));

        registry.RegisterSingleton<AuthenticationNavigationGuard>();

        return registry;
    }
}
