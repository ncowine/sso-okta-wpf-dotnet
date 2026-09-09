using System.Windows.Input;

namespace AppB;

/// <summary>
/// An <see cref="ICommand"/> for an async handler.
/// </summary>
/// <remarks>
/// <para>
/// Prism supplies <c>BindableBase</c> and <c>DelegateCommand</c>, and the view models use
/// them — but Prism 8 has no command type for an <c>async</c> handler, so this small one
/// stays. (AppA, which has no Prism, carries its own <c>ObservableObject</c> as well.)
/// </para>
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
