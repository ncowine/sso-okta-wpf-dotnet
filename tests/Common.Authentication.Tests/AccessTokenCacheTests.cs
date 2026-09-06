using Common.Authentication.Storage;

namespace Common.Authentication.Tests;

/// <summary>
/// The access-token cache, which decides when a token is too close to expiry to hand out.
/// </summary>
/// <remarks>
/// <para>
/// Small, but the timing rule matters. Hand out a token with two seconds left and the API
/// rejects it, the handler refreshes and retries, and the user waits through two round
/// trips for what should have been one. Refuse to cache too eagerly and every call pays
/// for a refresh.
/// </para>
/// <para>
/// The storage underneath is Microsoft's <c>MemoryCache</c>; what is tested here is the
/// ninety-second margin and the key isolation, which are ours.
/// </para>
/// </remarks>
public class AccessTokenCacheTests
{
    private static readonly TimeSpan Margin = TimeSpan.FromSeconds(90);

    [Fact]
    public void An_empty_cache_returns_nothing()
    {
        using var cache = new AccessTokenCache();

        Assert.False(cache.TryGet("Orders", out var token));
        Assert.Equal(string.Empty, token ?? string.Empty);
    }

    [Fact]
    public void A_token_with_plenty_of_life_is_returned()
    {
        using var cache = new AccessTokenCache();
        cache.Set("Orders", "token-abc", DateTimeOffset.UtcNow.AddMinutes(15));

        Assert.True(cache.TryGet("Orders", out var token));
        Assert.Equal("token-abc", token);
    }

    [Fact]
    public void A_token_already_inside_the_renewal_margin_is_not_cached()
    {
        using var cache = new AccessTokenCache();

        // Sixty seconds of life left, which is inside the ninety-second margin. Caching it
        // would hand out a token that is about to be refused.
        cache.Set("Orders", "nearly-expired", DateTimeOffset.UtcNow.AddSeconds(60));

        Assert.False(cache.TryGet("Orders", out _));
    }

    [Fact]
    public void An_already_expired_token_is_not_cached()
    {
        using var cache = new AccessTokenCache();
        cache.Set("Orders", "stale", DateTimeOffset.UtcNow.AddMinutes(-1));

        Assert.False(cache.TryGet("Orders", out _));
    }

    [Fact]
    public void A_token_just_outside_the_margin_is_cached()
    {
        using var cache = new AccessTokenCache();

        // The boundary in the useful direction: enough life that it is worth keeping.
        cache.Set("Orders", "fresh-enough", DateTimeOffset.UtcNow.Add(Margin).AddSeconds(30));

        Assert.True(cache.TryGet("Orders", out var token));
        Assert.Equal("fresh-enough", token);
    }

    [Fact]
    public void Resources_do_not_share_an_entry()
    {
        using var cache = new AccessTokenCache();

        cache.Set("Orders", "orders-token", DateTimeOffset.UtcNow.AddMinutes(15));
        cache.Set("Billing", "billing-token", DateTimeOffset.UtcNow.AddMinutes(15));

        // Two APIs mean two audiences. Serving one API's token to another would send a
        // token to somewhere it was never addressed.
        Assert.True(cache.TryGet("Orders", out var orders));
        Assert.True(cache.TryGet("Billing", out var billing));

        Assert.Equal("orders-token", orders);
        Assert.Equal("billing-token", billing);
    }

    [Fact]
    public void Removing_one_resource_leaves_the_others()
    {
        using var cache = new AccessTokenCache();

        cache.Set("Orders", "orders-token", DateTimeOffset.UtcNow.AddMinutes(15));
        cache.Set("Billing", "billing-token", DateTimeOffset.UtcNow.AddMinutes(15));

        // This is what happens after a 401: drop the one token the API refused, and let
        // the next call re-mint it. The others are still good.
        cache.Remove("Orders");

        Assert.False(cache.TryGet("Orders", out _));
        Assert.True(cache.TryGet("Billing", out _));
    }

    [Fact]
    public void Signing_out_forgets_every_token()
    {
        using var cache = new AccessTokenCache();

        cache.Set("Orders", "orders-token", DateTimeOffset.UtcNow.AddMinutes(15));
        cache.Set("Billing", "billing-token", DateTimeOffset.UtcNow.AddMinutes(15));

        cache.Clear(["Orders", "Billing"]);

        // Nothing may survive a sign-out. A token left behind would keep working until it
        // expired, which is exactly what the user asked us to stop.
        Assert.False(cache.TryGet("Orders", out _));
        Assert.False(cache.TryGet("Billing", out _));
    }

    [Fact]
    public void Replacing_a_token_returns_the_newer_one()
    {
        using var cache = new AccessTokenCache();

        cache.Set("Orders", "first", DateTimeOffset.UtcNow.AddMinutes(15));
        cache.Set("Orders", "second", DateTimeOffset.UtcNow.AddMinutes(15));

        Assert.True(cache.TryGet("Orders", out var token));
        Assert.Equal("second", token);
    }
}
