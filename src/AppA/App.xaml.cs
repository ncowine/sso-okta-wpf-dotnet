using System.Net.Http;
using System.Windows;
using AppA.Views;
using Corp.Identity.Client;
using Corp.Identity.Shell;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Prism.Ioc;
using Velopack;

namespace AppA;

/// <summary>
/// AppA bootstrapper. README §8.11.
/// </summary>
public partial class App
{
    private const string ApplicationName = "AppA";

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

        registry.RegisterIdentity(
            configuration,
            ApplicationName,
            interactionFactory: () => new WpfUserInteraction(ShellViewModel.Instance));

        registry.RegisterSingleton<IApiClient, ApiClient>();
        registry.RegisterForNavigation<HomeView, HomeViewModel>();
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
                    $"AppA could not sign you in and will close.\n\n" +
                    $"Reason: {result.Error} {result.ErrorDescription}".TrimEnd());

                Current.Shutdown();
                return;
            }

            Container.Resolve<SessionExpiryNotifier>().Start();

            Container.Resolve<Prism.Regions.IRegionManager>()
                     .RequestNavigate(RegionNames.Main, nameof(HomeView));
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

/// <summary>Typed access to ApiA. Tokens are attached by <see cref="OktaTokenHandler"/>.</summary>
public interface IApiClient
{
    Task<string> GetAsync(string path, CancellationToken ct = default);
}

public sealed class ApiClient : IApiClient
{
    private readonly HttpClient _http;

    public ApiClient(
        IAuthenticationService auth,
        Microsoft.Extensions.Options.IOptions<OktaClientOptions> options,
        ILoggerFactory loggerFactory)
    {
        var resource = options.Value.PrimaryResource;

        // The token handler sits in front of the transport, so nothing above this line
        // ever sees a token (README §8.10).
        var handler = new OktaTokenHandler(auth, resource.Name, loggerFactory.CreateLogger<OktaTokenHandler>())
        {
            InnerHandler = new HttpClientHandler(),
        };

        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(resource.BaseAddress),
            Timeout = TimeSpan.FromSeconds(30),
        };
    }

    public async Task<string> GetAsync(string path, CancellationToken ct = default)
    {
        using var response = await _http.GetAsync(path, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        return response.IsSuccessStatusCode
            ? body
            : $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}\n\n{body}";
    }
}
