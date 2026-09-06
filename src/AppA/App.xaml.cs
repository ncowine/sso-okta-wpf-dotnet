using System.Windows;
using Common.Authentication;
using Common.Authentication.Callback;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AppA;

/// <summary>
/// Everything this application does at startup, in the order it does it.
/// </summary>
/// <remarks>
/// Plain WPF and Microsoft dependency injection — no MVVM framework, no container
/// library. The whole of authentication is one call to <c>AddCommonAuthentication</c>.
/// </remarks>
public partial class App : Application
{
    private ServiceProvider? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
        // FIRST. Windows delivers a private-use-scheme callback by starting a second copy
        // of this executable with the URI as an argument. If that is why we are running,
        // hand it to the instance that is waiting and stop here.
        //
        // Harmless when the redirect is a loopback address — no callback ever arrives this
        // way, so it just claims the single-instance lock and returns.
        if (PrivateUriSchemeActivation.ForwardToRunningInstance(e.Args, "appa"))
        {
            Shutdown();
            return;
        }

        base.OnStartup(e);

        _services = BuildServices();

        // Any exception that escapes a command handler lands here. Without this the
        // process exits with code 0 and leaves nothing to diagnose.
        InstallCrashReporting();

        var shell = _services.GetRequiredService<ShellWindow>();
        MainWindow = shell;
        shell.Show();

        // Sign-in is started after the window is up, so the user has something to look at
        // while the browser opens. It cannot go in a view model constructor: constructors
        // cannot await, and blocking on the result deadlocks the dispatcher.
        _ = _services.GetRequiredService<ShellViewModel>().StartAsync();
    }

    private static ServiceProvider BuildServices()
    {
        var environment = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "Production";

        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{environment}.json", optional: true)
            .Build();

        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.AddConfiguration(configuration.GetSection("Logging"));
            logging.AddDebug();

            // A WinExe has no console, so this is silent under a normal launch. It only
            // produces output when stdout is redirected:
            //     dotnet run --project src/AppA > appa.log 2>&1
            // which is the quickest way to watch a sign-in actually happen.
            logging.AddSimpleConsole(o => o.SingleLine = true);
        });

        // Options, token storage, the protocol client, the callback listener, and a named
        // HttpClient per configured API with its token attached. That is the whole of it.
        services.AddCommonAuthentication(configuration);

        services.AddSingleton<ShellViewModel>();
        services.AddSingleton<OrdersViewModel>();
        services.AddSingleton<ShellWindow>();

        return services.BuildServiceProvider();
    }

    private void InstallCrashReporting()
    {
        var log = _services!.GetRequiredService<ILoggerFactory>().CreateLogger<App>();

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
        _services?.Dispose();
        base.OnExit(e);
    }
}
