using System.Net.Http;
using System.Windows;
using AppB.Modules;
using AppB.Views;
using Corp.Identity;
using Corp.Identity.Prism;
using Corp.Identity.Wpf;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Prism.Ioc;
using Prism.Modularity;
using Velopack;

namespace AppB;

/// <summary>
/// AppB bootstrapper. README §8.11.
/// </summary>
public partial class App
{
    private const string ApplicationName = "AppB";

    protected override void OnStartup(StartupEventArgs e)
    {
        // Velopack must run before ANY other startup work: on the very first run after
        // an install or update it performs the hook (shortcuts, Add/Remove Programs
        // entry, version swap) and exits the process. Anything above this line would
        // execute during install. See build/publish.ps1 and DEMO.md.
        VelopackApp.Build().Run();

#if TELERIK
        Telerik.Windows.Controls.StyleManager.ApplicationTheme =
            new Telerik.Windows.Controls.FluentTheme();
#endif

        base.OnStartup(e);
    }

    protected override Window CreateShell() => Container.Resolve<ShellWindow>();

    protected override void RegisterTypes(IContainerRegistry registry)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "Production"}.json",
                         optional: true)
            .Build();

        // One call wires the whole identity stack: options, token store, access-token
        // cache, the protocol client, the WPF interaction surface, and a named HttpClient
        // per resource with tokens attached. README §8.11.
        registry.RegisterIdentity(
            configuration,
            ApplicationName,
            busyHost: () => ShellViewModel.Instance,
            "ApiB");

        registry.RegisterSingleton<IApiClient, ApiClient>();
    }

    protected override void ConfigureModuleCatalog(IModuleCatalog catalog)
    {
        // Authentication loads first and unconditionally; feature modules load on demand
        // after sign-in, so they may assume an authenticated user (README §8.11).
        catalog.AddModule<AuthenticationModule>(InitializationMode.WhenAvailable);
        catalog.AddModule<BillingModule>(InitializationMode.OnDemand);
    }

    /// <summary>
    /// Sign-in happens here, not in a view model constructor: constructors cannot await,
    /// so you would get either a deadlock from .Result or a fire-and-forget that renders
    /// an unauthenticated shell for a few frames (README §8.11).
    /// </summary>
    protected override async void OnInitialized()
    {
        base.OnInitialized();

        var auth = Container.Resolve<IAuthenticationService>();
        var interaction = Container.Resolve<IUserInteraction>();

        // Every ICommand handler in a WPF/MVVM application is effectively async void, so
        // anything escaping one reaches DispatcherUnhandledException. With no handler the
        // process exits with code 0 and leaves no trace at all.
        this.UseCrashReporting(
            Container.Resolve<ILoggerFactory>().CreateLogger<App>(), interaction);

        try
        {
            AuthenticationResult result;

            using (interaction.ShowBusy("Restoring your session…"))
            {
                result = await auth.TryRestoreSessionAsync();
            }

            if (!result.Succeeded)
            {
                using (interaction.ShowBusy("Complete sign-in in your browser, then return here."))
                {
                    result = await auth.SignInAsync();
                }
            }

            if (!result.Succeeded)
            {
                await interaction.AlertAsync(
                    "Sign-in required",
                    $"AppB could not sign you in and will close.\n\n" +
                    $"Reason: {result.Error} {result.ErrorDescription}".TrimEnd());

                Current.Shutdown();
                return;
            }

            Container.Resolve<SessionExpiryNotifier>().Start();

            // Load the feature module now that a user is signed in. Its OnInitialized
            // performs the guarded navigation.
            Container.Resolve<IModuleManager>().LoadModule(nameof(BillingModule));
        }
        catch (Exception ex)
        {
            Container.Resolve<ILoggerFactory>()
                     .CreateLogger<App>()
                     .LogCritical(ex, "Startup authentication failed");

            await interaction.AlertAsync("Startup failed", ex.Message);
            Current.Shutdown();
        }
    }
}

public static class RegionNames
{
    public const string Main = "MainRegion";
}

/// <summary>Typed access to ApiB. Tokens are attached by <see cref="OktaTokenHandler"/>.</summary>
public interface IApiClient
{
    Task<string> GetAsync(string path, CancellationToken ct = default);
}

public sealed class ApiClient(IHttpClientFactory httpClientFactory) : IApiClient
{
    /// <summary>
    /// The logical resource name registered by <c>AddCorpApiClient</c>. The base address,
    /// the bearer token, the single refresh-and-retry on 401, and the §7 Pattern 3
    /// downstream header are all attached by that registration — this type only issues
    /// requests (README §8.10).
    /// </summary>
    private const string Resource = "ApiB";

    public async Task<string> GetAsync(string path, CancellationToken ct = default)
    {
        var http = httpClientFactory.CreateClient(Resource);

        using var response = await http.GetAsync(path, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        return response.IsSuccessStatusCode
            ? body
            : $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}" +
              Environment.NewLine + Environment.NewLine + body;
    }
}
