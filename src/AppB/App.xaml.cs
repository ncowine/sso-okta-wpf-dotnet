using System.Windows;
using Common.Authentication;
using Common.Authentication.Callback;
using DryIoc;
using DryIoc.Microsoft.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Prism.DryIoc;
using Prism.Ioc;

namespace AppB;

/// <summary>
/// Everything this application does at startup, in the order it does it.
/// </summary>
/// <remarks>
/// <para>
/// AppB is the Prism counterpart to AppA. AppA is plain WPF on Microsoft's dependency
/// injection; AppB runs on Prism 8 with the DryIoc container. The point of having both is
/// that <c>AddCommonAuthentication</c> is the same call in each — the library does not know
/// or care which host it is registered into.
/// </para>
/// <para>
/// The one seam is <see cref="CreateContainerExtension"/>. <c>AddCommonAuthentication</c>
/// is an <see cref="IServiceCollection"/> extension because the things it registers —
/// <c>IHttpClientFactory</c>, <c>IOptions&lt;T&gt;</c>, <c>ILogger&lt;T&gt;</c> — have no
/// other registration API. Prism 8 has no <c>RegisterServices(IServiceCollection)</c> (that
/// arrived in Prism 9), so the <see cref="IServiceCollection"/> is populated into DryIoc
/// directly and Prism is handed the same container. There is exactly one container; every
/// view model still resolves through <c>IContainerProvider</c> as usual.
/// </para>
/// </remarks>
public partial class App : PrismApplication
{
    private DryIocContainerExtension? _container;

    protected override void OnStartup(StartupEventArgs e)
    {
        // FIRST, before Prism bootstraps. Windows delivers a private-use-scheme callback by
        // starting a second copy of this executable with the URI as an argument. If that is
        // why we are running, hand it to the instance that is waiting and stop here.
        //
        // Harmless when the redirect is a loopback address — no callback ever arrives this
        // way, so it just claims the single-instance lock and returns.
        if (PrivateUriSchemeActivation.ForwardToRunningInstance(e.Args, "appb"))
        {
            Shutdown();
            return;
        }

        base.OnStartup(e);
    }

    /// <summary>
    /// Builds the one container: Prism's own rules, the auth stack registered through
    /// <see cref="IServiceCollection"/>, and the DryIoc &lt;-&gt; Microsoft DI adapter over
    /// the top so <c>IHttpClientFactory</c> and friends resolve.
    /// </summary>
    protected override IContainerExtension CreateContainerExtension()
    {
        var environment = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "Production";

        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{environment}.json", optional: true)
            .Build();

        var services = new ServiceCollection();

        services.AddSingleton<IConfiguration>(configuration);

        services.AddLogging(logging =>
        {
            logging.AddConfiguration(configuration.GetSection("Logging"));
            logging.AddDebug();

            // A WinExe has no console, so this is silent under a normal launch. It only
            // produces output when stdout is redirected:
            //     dotnet run --project src/AppB > appb.log 2>&1
            // which is the quickest way to watch a sign-in actually happen.
            logging.AddSimpleConsole(o => o.SingleLine = true);
        });

        // Options, token storage, the protocol client, the callback listener, and a named
        // HttpClient per configured API with its token attached. Identical to AppA.
        services.AddCommonAuthentication(configuration);

        // DryIocContainerExtension.DefaultRules carries what Prism needs — concrete-type
        // dynamic registration for views and view models, Func/Lazy without registration,
        // last-registration-wins. WithDependencyInjectionAdapter layers the Microsoft DI
        // resolution semantics on top and populates the descriptors, keeping both.
        var container = new Container(DryIocContainerExtension.DefaultRules)
            .WithDependencyInjectionAdapter(services, registerDescriptor: SkipConsoleFormatterOptionsBinding);

        _container = new DryIocContainerExtension(container);
        return _container;
    }

    /// <summary>
    /// The console logger registers a non-generic <c>ConsoleFormatterConfigureOptions</c> as
    /// <c>IConfigureOptions&lt;JsonConsoleFormatterOptions&gt;</c> (and the Simple/Systemd
    /// variants). Microsoft DI accepts that; DryIoc's stricter assignability check rejects
    /// it, and the DryIoc 4.x adapter that Prism 8 pins is too old to special-case it.
    /// Skipping these descriptors only drops the <i>default</i> binding of formatter options
    /// from <c>IConfiguration</c> — the explicit <c>AddSimpleConsole(o =&gt; …)</c> call above
    /// still applies — so the console output is unaffected.
    /// </summary>
    /// <returns><c>true</c> to tell the adapter the descriptor is handled and to skip it.</returns>
    private static bool SkipConsoleFormatterOptionsBinding(IRegistrator registrator, ServiceDescriptor descriptor) =>
        descriptor.ImplementationType?.FullName == "Microsoft.Extensions.Logging.ConsoleFormatterConfigureOptions";

    protected override void RegisterTypes(IContainerRegistry containerRegistry)
    {
        // The auth stack is already in the container. Only this application's own types
        // are left, and they are resolved by Prism like anything else.
        containerRegistry.RegisterSingleton<ShellViewModel>();
        containerRegistry.RegisterSingleton<BillingViewModel>();
    }

    protected override Window CreateShell() => Container.Resolve<ShellWindow>();

    protected override void OnInitialized()
    {
        // base.OnInitialized shows the shell. Do that before anything slow, so the user has
        // something to look at while the browser opens.
        base.OnInitialized();

        InstallCrashReporting();

        // Sign-in is started after the window is up. It cannot go in a view model
        // constructor: constructors cannot await, and blocking on the result deadlocks the
        // dispatcher. Resolving ShellViewModel here also forces IAuthenticationService — and
        // with it the redirect listener — to construct.
        _ = Container.Resolve<ShellViewModel>().StartAsync();
    }

    private void InstallCrashReporting()
    {
        var log = Container.Resolve<ILoggerFactory>().CreateLogger<App>();

        DispatcherUnhandledException += (_, args) =>
        {
            log.LogCritical(args.Exception, "Unhandled exception on the UI thread");

            MessageBox.Show(
                $"{args.Exception.Message}\n\nThe application will try to continue.",
                "Something went wrong", MessageBoxButton.OK, MessageBoxImage.Warning);

            // Handled: one failed command must not take the application down.
            args.Handled = true;
        };

        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            log.LogError(args.Exception, "Unobserved task exception");
            args.SetObserved();
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            // Not cancellable — the process is going down. Logging here is the difference
            // between a diagnosable crash and a window that simply vanishes.
            log.LogCritical(args.ExceptionObject as Exception, "Fatal error; the process is ending");
        };
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Disposes AuthenticationService (its SemaphoreSlim), the redirect listener, and the
        // token store, along with everything else DryIoc is tracking.
        _container?.Instance.Dispose();
        base.OnExit(e);
    }
}
