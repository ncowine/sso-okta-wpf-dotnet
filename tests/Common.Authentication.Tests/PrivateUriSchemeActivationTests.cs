using Common.Authentication.Callback;

namespace Common.Authentication.Tests;

/// <summary>
/// The single-instance gate, which decides whether a launch is the application or just a
/// courier carrying a sign-in response.
/// </summary>
/// <remarks>
/// <para>
/// These are a regression suite for a defect found by running the thing rather than by
/// reasoning about it. The gate originally decided using the result of a named-pipe write:
/// if forwarding worked, shut down; otherwise start normally. Two problems followed.
/// </para>
/// <para>
/// The pipe server handles one connection at a time, and a single sign-in produces two
/// callbacks in quick succession — the silent attempt failing with <c>login_required</c>,
/// then the interactive one succeeding. When the second arrived while the server was
/// between connections, the write failed, and the courier process started a <i>whole
/// second copy of the application</i>, complete with its own window and its own sign-in.
/// </para>
/// <para>
/// Nothing stopped it, because the mutex was taken with
/// <c>new Mutex(initiallyOwned: true, name)</c> — an overload that never reports whether
/// anyone else already held it. The single-instance guarantee was decorative.
/// </para>
/// <para>
/// The fix is that the <b>mutex</b> decides, and forwarding is best-effort afterwards.
/// </para>
/// </remarks>
public class PrivateUriSchemeActivationTests
{
    /// <summary>A scheme unique to each test, so tests never contend over one mutex.</summary>
    private static string UniqueScheme() => "test" + Guid.NewGuid().ToString("N")[..12];

    [Fact]
    public void A_normal_launch_becomes_the_application()
    {
        var shutDown = PrivateUriSchemeActivation.ForwardToRunningInstance([], UniqueScheme());

        Assert.False(shutDown);
    }

    [Fact]
    public void A_launch_carrying_a_callback_still_starts_when_nothing_is_running()
    {
        var scheme = UniqueScheme();

        // The user clicked a stale link with the application closed. Starting normally is
        // right; the callback belongs to a sign-in that no longer exists, and its code is
        // single-use and nearly expired anyway.
        var shutDown = PrivateUriSchemeActivation.ForwardToRunningInstance(
            [$"{scheme}://auth/callback?code=abc&state=xyz"], scheme);

        Assert.False(shutDown);
    }

    [Fact]
    public void Arguments_that_are_not_a_callback_are_ignored()
    {
        var scheme = UniqueScheme();

        var shutDown = PrivateUriSchemeActivation.ForwardToRunningInstance(
            ["--verbose", "C:\\some\\file.txt", "https://example.com"], scheme);

        Assert.False(shutDown);
    }

    [Fact]
    public void A_scheme_must_be_supplied()
    {
        // Passing "" would produce a mutex shared by every application using this library,
        // so exactly one of them could ever run. Fail loudly instead.
        Assert.Throws<ArgumentException>(
            () => PrivateUriSchemeActivation.ForwardToRunningInstance([], ""));
    }

    [Fact]
    public void The_scheme_match_is_case_insensitive()
    {
        var scheme = UniqueScheme();

        // Windows does not promise the casing it hands back, and neither do providers.
        var shutDown = PrivateUriSchemeActivation.ForwardToRunningInstance(
            [$"{scheme.ToUpperInvariant()}://AUTH/CALLBACK?code=abc"], scheme);

        Assert.False(shutDown);
    }

    /// <summary>
    /// The defect itself: with an instance already holding the mutex, a second launch must
    /// report "shut down" — whether or not it managed to forward anything.
    /// </summary>
    [Fact]
    public void A_second_launch_shuts_down_rather_than_starting_a_second_application()
    {
        var scheme = UniqueScheme();
        var mutexName = $"Local\\CommonAuth-{scheme}-{Environment.UserName}";

        // Stand in for an application already running. Nothing is listening on the pipe,
        // which is the case that used to produce a second window.
        using var alreadyRunning = new Mutex(initiallyOwned: true, mutexName, out var acquired);
        Assert.True(acquired, "the test's own mutex should be new");

        try
        {
            var shutDown = PrivateUriSchemeActivation.ForwardToRunningInstance(
                [$"{scheme}://auth/callback?code=abc&state=xyz"], scheme);

            Assert.True(shutDown);
        }
        finally
        {
            alreadyRunning.ReleaseMutex();
        }
    }

    [Fact]
    public void A_second_plain_launch_also_shuts_down()
    {
        var scheme = UniqueScheme();
        var mutexName = $"Local\\CommonAuth-{scheme}-{Environment.UserName}";

        using var alreadyRunning = new Mutex(initiallyOwned: true, mutexName, out _);

        try
        {
            // No callback URI at all — someone double-clicked the icon. Two copies would
            // otherwise fight over one token store.
            Assert.True(PrivateUriSchemeActivation.ForwardToRunningInstance([], scheme));
        }
        finally
        {
            alreadyRunning.ReleaseMutex();
        }
    }
}
