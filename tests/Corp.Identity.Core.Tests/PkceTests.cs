using System.Text.RegularExpressions;
using Corp.Identity.Protocol;

namespace Corp.Identity.Core.Tests;

/// <summary>
/// PKCE is what makes a public client safe without a secret. If the challenge derivation
/// is wrong the authorization server rejects every exchange; if the verifier is
/// predictable, PKCE protects nothing. Both are worth pinning.
/// </summary>
public class PkceTests
{
    /// <summary>
    /// RFC 7636 Appendix B, the specification's own worked example. This is the test that
    /// proves the derivation is S256 over the ASCII verifier, base64url without padding —
    /// every part of which is a place implementations go wrong.
    /// </summary>
    [Fact]
    public void Challenge_matches_the_RFC_7636_test_vector()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        Assert.Equal(expected, Pkce.Challenge(verifier));
    }

    [Fact]
    public void Verifier_is_base64url_within_the_length_RFC_7636_allows()
    {
        var verifier = Pkce.NewVerifier();

        Assert.InRange(verifier.Length, 43, 128);
        Assert.Matches(new Regex("^[A-Za-z0-9._~-]+$"), verifier);
    }

    [Fact]
    public void Challenge_carries_no_base64_padding()
    {
        // '=' and '+' and '/' are all legal base64 but not base64url, and a padded
        // challenge is silently rejected by the authorization server.
        var challenge = Pkce.Challenge(Pkce.NewVerifier());

        Assert.DoesNotContain('=', challenge);
        Assert.DoesNotContain('+', challenge);
        Assert.DoesNotContain('/', challenge);
    }

    [Theory]
    [InlineData(200)]
    public void Verifiers_states_and_nonces_are_never_reused(int samples)
    {
        // Not a statistical test of the RNG — just proof that nothing is cached or seeded
        // per process, which is the failure mode that would let one flow's state satisfy
        // another's check.
        Assert.Equal(samples, Enumerable.Range(0, samples).Select(_ => Pkce.NewVerifier()).Distinct().Count());
        Assert.Equal(samples, Enumerable.Range(0, samples).Select(_ => Pkce.NewState()).Distinct().Count());
        Assert.Equal(samples, Enumerable.Range(0, samples).Select(_ => Pkce.NewNonce()).Distinct().Count());
    }
}
