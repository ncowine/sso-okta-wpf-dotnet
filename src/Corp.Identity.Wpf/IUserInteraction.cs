namespace Corp.Identity.Wpf;

/// <summary>
/// The shell surface the authentication layer needs, kept behind an abstraction so the
/// solution builds without a Telerik licence. README §8.12.
/// </summary>
/// <remarks>
/// <para>Two implementations ship: <c>WpfUserInteraction</c> (plain WPF, always
/// available) and <c>TelerikUserInteraction</c> (compiled only when
/// <c>-p:UseTelerik=true</c>). Nothing outside this namespace references either
/// directly, so switching is a one-line registration change.</para>
/// </remarks>
public interface IUserInteraction
{
    /// <summary>
    /// Shows a modal busy state. The message should explain the BROWSER, not the
    /// mechanism — "Complete sign-in in your browser, then return here."
    /// </summary>
    IDisposable ShowBusy(string message);

    Task AlertAsync(string title, string message);

    Task<bool> ConfirmAsync(string title, string message);

    /// <summary>A non-blocking toast, e.g. the session-expiry warning.</summary>
    void Notify(string title, string message);

    /// <summary>Brings the main window back to the foreground after the browser redirect.</summary>
    void RestoreFocus();
}
