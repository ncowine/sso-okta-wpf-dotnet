using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace AppA;

/// <summary>
/// The two pieces of MVVM plumbing this application needs, so it can bind without
/// depending on an MVVM framework.
/// </summary>
/// <remarks>
/// About forty lines, and it replaces a third-party package. If your own application
/// already has a base view model, use that instead — nothing in
/// <c>Common.Authentication</c> cares which one you use.
/// </remarks>
public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Assigns a field and raises the change notification only if the value actually changed.</summary>
    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    protected void Raise([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

/// <summary>
/// An <see cref="ICommand"/> for an async handler.
/// </summary>
/// <remarks>
/// <para>
/// The important detail is that it <b>catches</b>. A command handler is invoked by WPF as
/// <c>async void</c>: nothing awaits it, so an exception that escapes goes straight to
/// <c>DispatcherUnhandledException</c>, and with no handler wired the process exits
/// silently with code 0. Catching here turns that into a message the user can read.
/// </para>
/// <para>
/// It also refuses to run twice at once, which stops a double-click firing two sign-ins.
/// </para>
/// </remarks>
public sealed class AsyncCommand(Func<Task> execute, Func<bool>? canExecute = null) : ICommand
{
    private bool _running;

    public event EventHandler? CanExecuteChanged;

    /// <summary>Reported to the UI when a command fails, so the shell can show it.</summary>
    public event Action<Exception>? Faulted;

    public bool CanExecute(object? parameter) => !_running && (canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;

        _running = true;
        RaiseCanExecuteChanged();

        try
        {
            await execute();
        }
        catch (Exception ex)
        {
            Faulted?.Invoke(ex);
        }
        finally
        {
            _running = false;
            RaiseCanExecuteChanged();
        }
    }

    public void RaiseCanExecuteChanged() =>
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
