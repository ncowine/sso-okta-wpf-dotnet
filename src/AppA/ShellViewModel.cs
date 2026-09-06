using System.Windows;
using Common.Authentication;

namespace AppA;

/// <summary>
/// The shell: who is signed in, whether we are busy, and the sign-out commands.
/// </summary>
/// <remarks>
/// Note what this class does <i>not</i> contain. No tokens, no expiry arithmetic, no
/// browser. It takes <see cref="IAuthenticationService"/>, listens for changes, and
/// exposes properties the XAML can bind to. That is the whole of the integration.
/// </remarks>
public sealed class ShellViewModel : ObservableObject
{
    private readonly IAuthenticationService _auth;
    private readonly OrdersViewModel _orders;

    private bool _isBusy;
    private string _busyMessage = string.Empty;
    private string _signedInAs = "Not signed in";
    private string _status = "Starting…";

    public ShellViewModel(IAuthenticationService auth, OrdersViewModel orders)
    {
        _auth = auth;
        _orders = orders;

        SignOutCommand = new AsyncCommand(
            () => SignOutAsync(SignOutScope.Application),
            () => _auth.IsSignedIn);

        SignOutEverywhereCommand = new AsyncCommand(
            () => SignOutAsync(SignOutScope.Everywhere),
            () => _auth.IsSignedIn);

        SignOutCommand.Faulted += ReportFault;
        SignOutEverywhereCommand.Faulted += ReportFault;

        // The service raises this from whatever thread finished the work, so everything
        // bindable has to be set on the UI thread.
        _auth.StateChanged += (_, e) => OnUiThread(() =>
        {
            SignedInAs = e.User?.FindFirst("preferred_username")?.Value
                         ?? e.User?.FindFirst("email")?.Value
                         ?? e.User?.FindFirst("sub")?.Value
                         ?? "Not signed in";

            Status = e.Reason switch
            {
                // The one the user did not ask for, and the only one worth interrupting
                // them about.
                AuthenticationChangeReason.SessionExpired =>
                    "Your session ended. Please sign in again.",

                AuthenticationChangeReason.SignedIn => "Signed in.",
                AuthenticationChangeReason.SessionRestored => "Welcome back.",
                AuthenticationChangeReason.SignedOut => "Signed out.",
                _ => Status,
            };

            RefreshCommands();
        });
    }

    public OrdersViewModel Orders => _orders;

    public bool IsBusy { get => _isBusy; private set => SetProperty(ref _isBusy, value); }
    public string BusyMessage { get => _busyMessage; private set => SetProperty(ref _busyMessage, value); }
    public string SignedInAs { get => _signedInAs; private set => SetProperty(ref _signedInAs, value); }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }

    public AsyncCommand SignOutCommand { get; }
    public AsyncCommand SignOutEverywhereCommand { get; }

    /// <summary>
    /// Gets the user signed in. Called once, after the window is showing.
    /// </summary>
    /// <remarks>
    /// Two attempts, and both are usually invisible. Restoring uses the refresh token
    /// stored last time. Signing in tries <c>prompt=none</c> first, which succeeds without
    /// a prompt whenever the user's browser already has a session with the provider —
    /// which it will if they opened the web dashboard this morning.
    /// </remarks>
    public async Task StartAsync()
    {
        using (Busy("Restoring your session…"))
        {
            var restored = await _auth.RestoreSessionAsync();
            if (restored.Succeeded) return;
        }

        using (Busy("Complete sign-in in your browser, then come back here."))
        {
            var result = await _auth.SignInAsync();

            if (!result.Succeeded)
            {
                Status = result.ToDisplayMessage();

                MessageBox.Show(
                    $"{result.ToDisplayMessage()}\n\nAppA will close.",
                    "Sign-in required", MessageBoxButton.OK, MessageBoxImage.Information);

                Application.Current.Shutdown();
            }
        }
    }

    private async Task SignOutAsync(SignOutScope scope)
    {
        if (scope == SignOutScope.Everywhere)
        {
            // Worth asking. Signing out of everything is the correct meaning of single
            // sign-out, and it is reported as a bug roughly every time it happens without
            // warning.
            var confirmed = MessageBox.Show(
                "This ends your session with the identity provider, so you will be signed " +
                "out of every other application too.\n\nContinue?",
                "Sign out everywhere?",
                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

            if (!confirmed) return;
        }

        using (Busy("Signing out…"))
        {
            await _auth.SignOutAsync(scope);
        }

        if (scope == SignOutScope.Everywhere) Application.Current.Shutdown();
    }

    private void ReportFault(Exception ex) => OnUiThread(() => Status = ex.Message);

    private void RefreshCommands()
    {
        SignOutCommand.RaiseCanExecuteChanged();
        SignOutEverywhereCommand.RaiseCanExecuteChanged();
    }

    /// <summary>Shows the busy overlay until the returned scope is disposed.</summary>
    private IDisposable Busy(string message)
    {
        OnUiThread(() =>
        {
            BusyMessage = message;
            IsBusy = true;
        });

        return new BusyScope(() => OnUiThread(() => IsBusy = false));
    }

    private static void OnUiThread(Action action)
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
