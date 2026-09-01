using System.Reflection;
using Corp.Identity.Client;
using Prism.Regions;

namespace Corp.Identity.Shell;

/// <summary>
/// Marks a view as requiring one or more scopes before it may be navigated to.
/// </summary>
/// <remarks>
/// ⚠️ Client-side gating is UX, not security. It stops a user opening a screen they
/// cannot use; it stops nothing else — a modified client or a plain curl bypasses it
/// entirely. Every rule enforced here MUST be enforced again in the API
/// (README §8.13, §9.3).
/// </remarks>
[AttributeUsage(AttributeTargets.Class)]
public sealed class RequiresScopeAttribute(params string[] scopes) : Attribute
{
    public IReadOnlyList<string> Scopes { get; } = scopes;
}

/// <summary>
/// Decides whether the signed-in user may open a view, so the view is never constructed
/// for someone who cannot use it. README §8.13.
/// </summary>
/// <remarks>
/// Prism 8's <c>IRegionNavigationService.Navigating</c> event is not cancellable, so the
/// check happens BEFORE the navigation request rather than during it — use
/// <see cref="NavigationExtensions.RequestNavigateGuarded"/> instead of
/// <c>RequestNavigate</c>. View models that need to veto navigation for other reasons
/// should implement Prism's <c>IConfirmNavigationRequest</c> as usual.
/// </remarks>
public sealed class AuthenticationNavigationGuard(IAuthenticationService auth)
{
    /// <summary>Missing scopes for the named view, or an empty list when navigation is allowed.</summary>
    public IReadOnlyList<string> MissingScopesFor(string viewName)
    {
        var required = ResolveViewType(viewName)?.GetCustomAttribute<RequiresScopeAttribute>();
        if (required is null) return [];

        if (!auth.IsAuthenticated) return required.Scopes;

        return required.Scopes.Where(scope => !auth.HasScope(scope)).ToArray();
    }

    public bool CanNavigateTo(string viewName) => MissingScopesFor(viewName).Count == 0;

    private static Type? ResolveViewType(string viewName)
    {
        var name = viewName.Split('?')[0];

        return AppDomain.CurrentDomain.GetAssemblies()
            .SelectMany(SafeGetTypes)
            .FirstOrDefault(t => t.Name.Equals(name, StringComparison.Ordinal));
    }

    private static IEnumerable<Type> SafeGetTypes(Assembly assembly)
    {
        try { return assembly.GetTypes(); }
        catch (ReflectionTypeLoadException ex) { return ex.Types.OfType<Type>(); }
    }
}

public static class NavigationExtensions
{
    /// <summary>
    /// Navigates only if the user holds the view's <see cref="RequiresScopeAttribute"/>
    /// scopes, otherwise explains why not.
    /// </summary>
    public static void RequestNavigateGuarded(
        this IRegionManager regionManager,
        string regionName,
        string viewName,
        AuthenticationNavigationGuard guard,
        IUserInteraction interaction)
    {
        var missing = guard.MissingScopesFor(viewName);

        if (missing.Count == 0)
        {
            regionManager.RequestNavigate(regionName, viewName);
            return;
        }

        _ = interaction.AlertAsync(
            "Access denied",
            $"You do not have permission to open this screen.\n\nMissing: {string.Join(", ", missing)}\n\n" +
            "Ask an administrator to check your group membership in Okta.");
    }
}
