using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace Corp.Identity;

/// <summary>
/// Attaches a bearer token to outbound calls, so view models and repositories stay
/// entirely ignorant of tokens. README §8.10.
/// </summary>
public sealed class OktaTokenHandler(
    IAuthenticationService auth,
    string resourceName,
    ILogger<OktaTokenHandler> log) : DelegatingHandler
{
    /// <summary>
    /// Marks a request that has already been retried once. This is what prevents an
    /// infinite 401 loop when the API rejects tokens for a reason refreshing cannot fix
    /// — a misconfigured audience, say. Exactly one retry, always.
    /// </summary>
    private const string RetryMarker = "X-Corp-Auth-Retried";

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var token = await auth.GetAccessTokenAsync(resourceName, ct).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await base.SendAsync(request, ct).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Unauthorized || request.Headers.Contains(RetryMarker))
            return response;

        // A 401 despite a locally-valid token: revoked, key rotated, or clock skew.
        // Force one refresh and retry exactly once.
        log.LogInformation("401 from {Resource}; forcing token refresh and retrying once", resourceName);
        response.Dispose();

        auth.InvalidateAccessToken(resourceName);
        var fresh = await auth.GetAccessTokenAsync(resourceName, ct).ConfigureAwait(false);

        // An HttpRequestMessage cannot be sent twice — clone it, including the body,
        // which must be buffered to be replayable.
        using var retry = await CloneAsync(request, ct).ConfigureAwait(false);
        retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fresh);
        retry.Headers.TryAddWithoutValidation(RetryMarker, "1");

        return await base.SendAsync(retry, ct).ConfigureAwait(false);
    }

    internal static async Task<HttpRequestMessage> CloneAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy,
        };

        if (request.Content is not null)
        {
            var buffer = await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            clone.Content = new ByteArrayContent(buffer);
            foreach (var header in request.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        foreach (var header in request.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        foreach (var option in request.Options)
            clone.Options.Set(new HttpRequestOptionsKey<object?>(option.Key), option.Value);

        return clone;
    }
}
