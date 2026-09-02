using Corp.Identity;
using Corp.Identity.Wpf;
using Prism.Ioc;
using Prism.Modularity;

namespace Corp.Identity.Prism;

/// <summary>
/// Loads the identity stack as a Prism module. README §8.11.
/// </summary>
/// <remarks>
/// Registered with <see cref="InitializationMode.WhenAvailable"/> so it initialises before
/// any on-demand feature module — every other module may then assume an
/// <see cref="IAuthenticationService"/> exists and is initialised.
/// </remarks>
public sealed class AuthenticationModule : IModule
{
    public void RegisterTypes(IContainerRegistry containerRegistry)
    {
        // The identity singletons are registered by IdentityBootstrapper before the
        // module catalog runs, because the shell needs them during CreateShell().
        // This module owns lifecycle, not registration.
    }

    public void OnInitialized(IContainerProvider containerProvider)
    {
        var auth = containerProvider.Resolve<IAuthenticationService>();
        var interaction = containerProvider.Resolve<IUserInteraction>();

        // A single place to react to session loss, wherever it happens.
        auth.StateChanged += (_, e) =>
        {
            if (e.Reason != AuthenticationChangeReason.SessionExpired) return;

            interaction.Notify(
                "Session ended",
                "Your sign-in is no longer valid. Please sign in again.");
        };
    }
}

/// <summary>
/// Base class for feature modules that require an authenticated user, so the requirement
/// is declared rather than assumed.
/// </summary>
public abstract class AuthenticatedModule : IModule
{
    public abstract void RegisterTypes(IContainerRegistry containerRegistry);

    public void OnInitialized(IContainerProvider containerProvider)
    {
        var auth = containerProvider.Resolve<IAuthenticationService>();

        if (!auth.IsAuthenticated)
        {
            throw new InvalidOperationException(
                $"{GetType().Name} was initialised before authentication completed. " +
                "Load it with InitializationMode.OnDemand and request it after sign-in, " +
                "or ensure AuthenticationModule is registered WhenAvailable (README §8.11).");
        }

        OnAuthenticatedInitialized(containerProvider, auth);
    }

    protected abstract void OnAuthenticatedInitialized(
        IContainerProvider containerProvider, IAuthenticationService auth);
}
