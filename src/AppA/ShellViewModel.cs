using System.Windows;
using Corp.Identity;
using Corp.Identity.Prism;
using Corp.Identity.Wpf;
using Prism.Commands;
using Prism.Mvvm;

namespace AppA;

public sealed class ShellViewModel : BindableBase, IBusyHost
{
    /// <summary>
    /// Set during construction so <see cref="WpfUserInteraction"/> can drive the busy
    /// overlay. A single shell means a single instance; this avoids a circular
    /// registration between the view model and the interaction service.
    /// </summary>
    public static ShellViewModel Instance { get; private set; } = null!;

    private readonly IAuthenticationService _auth;
    private readonly IUserInteraction _interaction;

    private bool _isBusy;
    private string _busyMessage = string.Empty;
    private string _signedInAs = "Not signed in";
    private string _statusMessage = "Ready.";

    public ShellViewModel(IAuthenticationService auth, IUserInteraction interaction)
    {
        _auth = auth;
        _interaction = interaction;
        Instance = this;

        SignOutLocalCommand = new DelegateCommand(async () => await SignOutAsync(SignOutScope.Local));
        SignOutGlobalCommand = new DelegateCommand(async () => await SignOutAsync(SignOutScope.Global));

        _auth.StateChanged += (_, e) =>
        {
            var subject = e.User?.FindFirst("preferred_username")?.Value
                          ?? e.User?.FindFirst("email")?.Value
                          ?? e.User?.FindFirst("sub")?.Value;

            SignedInAs = subject is null ? "Not signed in" : $"Signed in as {subject}";
            StatusMessage = $"{e.Reason} at {DateTime.Now:HH:mm:ss}";
        };
    }

    public bool IsBusy { get => _isBusy; private set => SetProperty(ref _isBusy, value); }
    public string BusyMessage { get => _busyMessage; private set => SetProperty(ref _busyMessage, value); }
    public string SignedInAs { get => _signedInAs; private set => SetProperty(ref _signedInAs, value); }
    public string StatusMessage { get => _statusMessage; private set => SetProperty(ref _statusMessage, value); }

    public DelegateCommand SignOutLocalCommand { get; }
    public DelegateCommand SignOutGlobalCommand { get; }

    public void SetBusy(bool isBusy, string? message)
    {
        IsBusy = isBusy;
        BusyMessage = message ?? string.Empty;
    }

    public void SetNotification(string message) => StatusMessage = message;

    private async Task SignOutAsync(SignOutScope scope)
    {
        if (scope == SignOutScope.Global)
        {
            // Global sign-out from AppA signs the user out of AppB too. That is the
            // correct meaning of SSO — one session, one sign-out — but it surprises
            // users and will be reported as a bug unless you say so (README §11.2).
            var confirmed = await _interaction.ConfirmAsync(
                "Sign out of all applications?",
                "This ends your Okta session. You will be signed out of AppB and every " +
                "other Corp application, on this machine and any other browser session.");

            if (!confirmed) return;
        }

        using (_interaction.ShowBusy("Signing out…"))
        {
            await _auth.SignOutAsync(scope);
        }

        if (scope == SignOutScope.Global) Application.Current.Shutdown();
    }
}
