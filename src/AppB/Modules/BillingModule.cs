using AppB.Views;
using Corp.Identity;
using Corp.Identity.Prism;
using Corp.Identity.Wpf;
using Prism.Ioc;
using Prism.Regions;

namespace AppB.Modules;

/// <summary>
/// AppB's feature module. Loaded on demand, after sign-in has completed. README §8.11.
/// </summary>
public sealed class BillingModule : AuthenticatedModule
{
    public override void RegisterTypes(IContainerRegistry containerRegistry)
    {
        containerRegistry.RegisterForNavigation<HomeView, HomeViewModel>();
    }

    protected override void OnAuthenticatedInitialized(
        IContainerProvider containerProvider, IAuthenticationService auth)
    {
        var regions = containerProvider.Resolve<IRegionManager>();
        var guard = containerProvider.Resolve<AuthenticationNavigationGuard>();
        var interaction = containerProvider.Resolve<IUserInteraction>();

        // Guarded navigation: the view declares [RequiresScope("apib.read")], and a user
        // without it gets an explanation rather than a broken screen. UX only — ApiB
        // enforces the same rule server-side (README §8.13).
        regions.RequestNavigateGuarded(
            RegionNames.Main, nameof(HomeView), guard, interaction);
    }
}
