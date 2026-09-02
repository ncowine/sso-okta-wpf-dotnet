using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Corp.Identity.Wpf;

/// <summary>
/// The WPF half of the identity stack: dialogs, the busy overlay, focus restoration, and
/// a last-resort crash handler. No Prism, no DI container beyond the Microsoft
/// abstractions.
/// </summary>
/// <remarks>
/// A plain WPF application wires the whole thing up like this:
/// <code>
/// services.AddCorpIdentity(configuration, "AppA", WpfIdentity.FocusRestorer);
/// services.AddCorpIdentityWpf(() => MyShellViewModel.Instance);
/// </code>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class WpfIdentityExtensions
{
    /// <param name="busyHost">
    /// Resolved lazily, per call. The shell view model normally takes
    /// <see cref="IUserInteraction"/> in its own constructor, so at registration time it
    /// does not exist yet — capturing it eagerly captures null.
    /// </param>
    public static IServiceCollection AddCorpIdentityWpf(
        this IServiceCollection services, Func<IBusyHost?> busyHost)
    {
        services.AddSingleton<IUserInteraction>(_ => new WpfUserInteraction(busyHost));
        services.AddSingleton<SessionExpiryNotifier>();
        return services;
    }

    /// <summary>
    /// Brings the main window back to the foreground after the browser redirect. Pass to
    /// <c>AddCorpIdentity</c>; without it the user is left looking at a browser tab.
    /// </summary>
    /// <remarks>
    /// The redirect completes on a thread-pool thread, so this MUST marshal: every WPF
    /// object has thread affinity, and even reading <see cref="Application.MainWindow"/>
    /// from elsewhere throws.
    /// </remarks>
    public static Func<Action?> FocusRestorer { get; } = () => static () => Dispatch(() =>
    {
        var window = Application.Current?.MainWindow;
        if (window is null) return;

        if (window.WindowState == WindowState.Minimized)
            window.WindowState = WindowState.Normal;

        window.Activate();

        // Topmost on then off is the documented way to steal focus back from the browser
        // without leaving the window pinned above everything else.
        window.Topmost = true;
        window.Topmost = false;
        window.Focus();
    });

    /// <summary>
    /// Installs handlers for the three ways an exception escapes a WPF application, so a
    /// failure produces a message and a log entry rather than a window that simply
    /// disappears.
    /// </summary>
    /// <remarks>
    /// <para>Call once, first thing in <c>OnStartup</c>. It matters more than it looks:
    /// every ICommand handler in a WPF/MVVM application is effectively <c>async void</c>,
    /// so anything that escapes one reaches
    /// <see cref="Application.DispatcherUnhandledException"/> — and with no handler the
    /// process exits with code 0 and no trace at all.</para>
    /// <para>Dispatcher and unobserved-task exceptions are handled and reported;
    /// <see cref="AppDomain.UnhandledException"/> cannot be cancelled, so it is logged on
    /// the way down and nothing more.</para>
    /// </remarks>
    public static void UseCrashReporting(
        this Application application, ILogger logger, IUserInteraction interaction)
    {
        application.DispatcherUnhandledException += (_, e) =>
        {
            logger.LogCritical(e.Exception, "Unhandled exception on the UI thread");

            _ = interaction.AlertAsync(
                "Something went wrong",
                $"{e.Exception.Message}\n\nThe application will try to continue. If it " +
                "misbehaves, restart it.");

            // Handled: a failed command must not take the whole application down.
            e.Handled = true;
        };

        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            logger.LogError(e.Exception, "Unobserved task exception");
            e.SetObserved();
        };

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            // Not cancellable — the process is going down either way. Logging here is the
            // difference between a diagnosable crash and a silent disappearance.
            logger.LogCritical(e.ExceptionObject as Exception, "Unhandled exception; the process is terminating");
        };
    }

    /// <summary>Runs an action on the UI thread, whichever thread the caller is on.</summary>
    internal static void Dispatch(Action action)
    {
        Dispatcher? dispatcher = Application.Current?.Dispatcher;

        if (dispatcher is null || dispatcher.CheckAccess()) action();
        else dispatcher.Invoke(action);
    }
}
