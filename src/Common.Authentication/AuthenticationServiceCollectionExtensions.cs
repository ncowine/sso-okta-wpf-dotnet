using System.Runtime.Versioning;
using Common.Authentication.Callback;
using Common.Authentication.Http;
using Common.Authentication.Protocol;
using Common.Authentication.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Common.Authentication;

/// <summary>
/// One call to wire the whole thing up.
/// </summary>
/// <remarks>
/// <para>In your WPF application's composition root:</para>
/// <code>
/// services.AddCommonAuthentication(configuration);
/// </code>
/// <para>Then inject <see cref="IAuthenticationService"/> into a view model, and inject
/// <c>IHttpClientFactory</c> where you call an API:</para>
/// <code>
/// var http = factory.CreateClient("Orders");   // token already attached
/// var orders = await http.GetFromJsonAsync&lt;Order[]&gt;("orders");
/// </code>
/// <para>
/// And in <c>App.OnStartup</c>, before anything else, if you use a private-use scheme:
/// </para>
/// <code>
/// if (PrivateUriSchemeActivation.ForwardToRunningInstance(e.Args, "myapp"))
/// {
///     Shutdown();
///     return;
/// }
/// </code>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Registers everything needed to sign a user in and to call the configured APIs.
    /// </summary>
    /// <param name="configuration">
    /// Your configuration root. The <c>Authentication</c> section is read from it.
    /// </param>
    /// <param name="sectionName">
    /// Override if your settings live under a different key.
    /// </param>
    /// <remarks>
    /// Logging providers are not added here. Whatever your host has already configured is
    /// what this library writes to, which is how it should be — a library that installs its
    /// own log sink is a library that fights your application.
    /// </remarks>
    public static IServiceCollection AddCommonAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = AuthenticationOptions.SectionName)
    {
        services
            .AddOptions<AuthenticationOptions>()
            .Bind(configuration.GetSection(sectionName))
            .PostConfigure(options =>
            {
                // Let each resource know the name it was configured under, so callers can
                // say "Orders" instead of repeating an audience URI.
                foreach (var (name, resource) in options.Resources) resource.Name = name;

                options.ApplicationName ??=
                    System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name ?? "Application";
            })
            .Validate(options =>
            {
                options.Validate();
                return true;
            });

        // A plain client for protocol calls. It must NOT have a token handler on it:
        // fetching a token would then require a token.
        services.AddHttpClient(OpenIdConnectClient.HttpClientName);

        services.AddSingleton<ITokenStore>(provider => new DpapiTokenStore(
            provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value,
            provider.GetRequiredService<ILogger<DpapiTokenStore>>()));

        services.AddSingleton<AccessTokenCache>();

        // Which listener we need is decided by the shape of the redirect URI, so nobody
        // has to configure the same fact twice.
        services.AddSingleton<IRedirectListener>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
            var log = provider.GetRequiredService<ILoggerFactory>().CreateLogger("Common.Authentication.Callback");

            IRedirectListener listener = options.UsesPrivateUriScheme
                ? new PrivateUriSchemeListener(options, log)
                : new LoopbackListener(options, log);

            // Registers the scheme and starts listening for callbacks forwarded from a
            // second launch. Cheap, and idempotent.
            listener.Start();

            return listener;
        });

        services.AddSingleton(provider => new OpenIdConnectClient(
            provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value,
            provider.GetRequiredService<IRedirectListener>(),
            provider.GetRequiredService<IHttpClientFactory>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger("Common.Authentication.Protocol")));

        services.AddSingleton<IAuthenticationService, AuthenticationService>();

        // One named HttpClient per configured API, each with its token attached.
        RegisterApiClients(services, configuration, sectionName);

        return services;
    }

    /// <summary>
    /// Creates a named <c>HttpClient</c> for every entry under <c>Authentication:Resources</c>.
    /// </summary>
    /// <remarks>
    /// Read straight from configuration rather than from options, because the service
    /// provider does not exist yet at registration time and we need the names now.
    /// </remarks>
    private static void RegisterApiClients(
        IServiceCollection services, IConfiguration configuration, string sectionName)
    {
        var resources = configuration.GetSection($"{sectionName}:Resources").GetChildren();

        foreach (var resource in resources)
        {
            var name = resource.Key;

            services
                .AddHttpClient(name, (provider, http) =>
                {
                    var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

                    if (options.Resources.TryGetValue(name, out var configured) &&
                        !string.IsNullOrWhiteSpace(configured.BaseAddress))
                    {
                        http.BaseAddress = new Uri(configured.BaseAddress);
                    }

                    http.Timeout = TimeSpan.FromSeconds(30);
                })
                .AddHttpMessageHandler(provider => new AccessTokenHandler(
                    provider.GetRequiredService<IAuthenticationService>(),
                    name,
                    provider.GetRequiredService<ILogger<AccessTokenHandler>>()));
        }
    }
}
