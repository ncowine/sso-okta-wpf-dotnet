#if TELERIK
using System.Windows;
using Telerik.Windows.Controls;

namespace Corp.Identity.Wpf;

/// <summary>
/// Telerik implementation. Compiled ONLY when built with <c>-p:UseTelerik=true</c>,
/// which requires your licensed Telerik NuGet feed. README §8.12.
/// </summary>
/// <remarks>
/// Register it instead of <see cref="WpfUserInteraction"/> in the app bootstrapper, and
/// set the theme before any window is created:
/// <code>StyleManager.ApplicationTheme = new FluentTheme();</code>
/// </remarks>
public sealed class TelerikUserInteraction(Func<IBusyHost?> busyHost) : IUserInteraction
{
    public IDisposable ShowBusy(string message)
    {
        // Bound to RadBusyIndicator.IsBusy / BusyContent in the shell (see ShellWindow).
        Dispatch(() => busyHost()?.SetBusy(true, message));
        return new BusyScope(() => Dispatch(() => busyHost()?.SetBusy(false, null)));
    }

    public Task AlertAsync(string title, string message)
    {
        var tcs = new TaskCompletionSource();

        Dispatch(() => RadWindow.Alert(new DialogParameters
        {
            Header = title,
            Content = message,
            Closed = (_, _) => tcs.TrySetResult(),
        }));

        return tcs.Task;
    }

    public Task<bool> ConfirmAsync(string title, string message)
    {
        var tcs = new TaskCompletionSource<bool>();

        Dispatch(() => RadWindow.Confirm(new DialogParameters
        {
            Header = title,
            Content = message,
            Closed = (_, args) => tcs.TrySetResult(args.DialogResult == true),
        }));

        return tcs.Task;
    }

    public void Notify(string title, string message) => Dispatch(() =>
        RadDesktopAlertManager.Instance.ShowAlert(new DesktopAlertParameters
        {
            Header = title,
            Content = message,
            ShowDuration = 10_000,
        }));

    public void RestoreFocus() => Dispatch(() =>
    {
        var window = Application.Current?.MainWindow;
        if (window is null) return;

        if (window.WindowState == WindowState.Minimized)
            window.WindowState = WindowState.Normal;

        window.Activate();
        window.Focus();
    });

    private static void Dispatch(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;

        if (dispatcher is null || dispatcher.CheckAccess()) action();
        else dispatcher.Invoke(action);
    }

    private sealed class BusyScope(Action onDispose) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            onDispose();
        }
    }
}
#endif
