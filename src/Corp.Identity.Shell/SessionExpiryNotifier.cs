using Corp.Identity.Client;
using Microsoft.Win32;
using System.Windows.Threading;

namespace Corp.Identity.Shell;

/// <summary>
/// Warns before the session lapses, and re-checks it after the machine wakes.
/// README §8.8, §8.12.
/// </summary>
public sealed class SessionExpiryNotifier(
    IAuthenticationService auth,
    IUserInteraction interaction) : IDisposable
{
    private static readonly TimeSpan WarnAt = TimeSpan.FromMinutes(5);

    private DispatcherTimer? _timer;
    private bool _warned;
    private bool _disposed;

    public void Start()
    {
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(1) };
        _timer.Tick += OnTick;
        _timer.Start();

        // Desktop machines sleep. A laptop closed at 17:00 and reopened at 09:00 resumes
        // with timers that never fired and a refresh token that may have aged past its
        // idle window. Without this the user meets a wall of failed requests instead of
        // a clean prompt (README §8.8).
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
    }

    private void OnTick(object? sender, EventArgs e)
    {
        if (!auth.IsAuthenticated) return;

        var remaining = auth.TimeUntilSessionExpiry();

        if (remaining > WarnAt)
        {
            _warned = false;
            return;
        }

        if (_warned) return;
        _warned = true;

        interaction.Notify(
            "Session expiring",
            "Your sign-in expires in under five minutes. Save any work in progress.");
    }

    private async void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode != PowerModes.Resume) return;

        try
        {
            var result = await auth.TryRestoreSessionAsync();

            if (!result.Succeeded)
            {
                interaction.Notify(
                    "Signed out",
                    "Your session expired while this machine was asleep. Please sign in again.");
            }
        }
        catch (Exception)
        {
            // Never let a resume handler take the process down.
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        SystemEvents.PowerModeChanged -= OnPowerModeChanged;

        if (_timer is null) return;
        _timer.Stop();
        _timer.Tick -= OnTick;
    }
}
