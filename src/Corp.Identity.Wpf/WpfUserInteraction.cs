using System.Windows;

namespace Corp.Identity.Wpf;

/// <summary>
/// Plain-WPF implementation. Always available, no licence required. README §8.12.
/// </summary>
/// <remarks>
/// Swap for <c>TelerikUserInteraction</c> by building with <c>-p:UseTelerik=true</c>
/// once your Telerik feed is configured — see DEMO.md "Enabling Telerik".
/// </remarks>
public sealed class WpfUserInteraction : IUserInteraction
{
    private readonly Func<IBusyHost?> _busyHost;

    /// <param name="busyHost">
    /// Resolved lazily, per call. The shell view model takes <see cref="IUserInteraction"/>
    /// in its own constructor, so at the moment this type is built the view model does not
    /// exist yet — passing the instance eagerly captures null and the first
    /// <see cref="ShowBusy"/> throws.
    /// </param>
    public WpfUserInteraction(Func<IBusyHost?> busyHost) => _busyHost = busyHost;

    public IDisposable ShowBusy(string message)
    {
        Dispatch(() => _busyHost()?.SetBusy(true, message));
        return new BusyScope(() => Dispatch(() => _busyHost()?.SetBusy(false, null)));
    }

    public Task AlertAsync(string title, string message)
    {
        Dispatch(() => MessageBox.Show(
            Application.Current?.MainWindow!, message, title,
            MessageBoxButton.OK, MessageBoxImage.Information));

        return Task.CompletedTask;
    }

    public Task<bool> ConfirmAsync(string title, string message)
    {
        var result = MessageBoxResult.No;
        Dispatch(() => result = MessageBox.Show(
            Application.Current?.MainWindow!, message, title,
            MessageBoxButton.YesNo, MessageBoxImage.Question));

        return Task.FromResult(result == MessageBoxResult.Yes);
    }

    public void Notify(string title, string message) =>
        Dispatch(() => _busyHost()?.SetNotification($"{title} — {message}"));

    public void RestoreFocus() => Dispatch(() =>
    {
        var window = Application.Current?.MainWindow;
        if (window is null) return;

        if (window.WindowState == WindowState.Minimized)
            window.WindowState = WindowState.Normal;

        window.Activate();
        window.Topmost = true;
        window.Topmost = false;
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

/// <summary>
/// Implemented by the shell view model so <see cref="WpfUserInteraction"/> can drive the
/// busy overlay without knowing anything about the view.
/// </summary>
public interface IBusyHost
{
    void SetBusy(bool isBusy, string? message);
    void SetNotification(string message);
}
