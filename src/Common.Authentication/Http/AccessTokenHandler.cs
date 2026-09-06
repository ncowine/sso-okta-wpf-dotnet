using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace Common.Authentication.Http;

/// <summary>
/// Attaches the bearer token to every outgoing call, so nothing above this line has to
/// know tokens exist.
/// </summary>
/// <remarks>
/// <para>
/// This is the piece that keeps your view models clean. They inject a typed or named
/// <c>HttpClient</c>, call <c>GetAsync("orders")</c>, and never see a token, a refresh, or
/// an expiry.
/// </para>
/// <para>
/// It also retries once on a 401. A token can be revoked, or the provider can rotate its
/// keys, between us minting a token and the API reading it. One forced refresh and one
/// retry turns that into a slightly slow request instead of an error in front of the user.
/// </para>
/// </remarks>
internal sealed class AccessTokenHandler(
    IAuthenticationService authentication,
    string resourceName,
    ILogger<AccessTokenHandler> log) : DelegatingHandler
{
    /// <summary>
    /// Marks a request we have already retried.
    /// </summary>
    /// <remarks>
    /// Without this, an API that returns 401 for a reason refreshing cannot fix — a
    /// misconfigured audience, say — sends us round forever. Exactly one retry, always.
    /// </remarks>
    private const string AlreadyRetried = "X-Auth-Retried";

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await authentication.GetAccessTokenAsync(resourceName, cancellationToken)
            .ConfigureAwait(false);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Unauthorized || request.Headers.Contains(AlreadyRetried))
        {
            return response;
        }

        log.LogInformation(
            "{Resource} rejected a token that looked valid; refreshing and retrying once", resourceName);

        response.Dispose();

        authentication.InvalidateAccessToken(resourceName);

        var fresh = await authentication.GetAccessTokenAsync(resourceName, cancellationToken)
            .ConfigureAwait(false);

        // An HttpRequestMessage cannot be sent twice, so the retry needs a copy — including
        // the body, which has to be buffered to be replayable.
        using var retry = await CloneAsync(request, cancellationToken).ConfigureAwait(false);

        retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fresh);
        retry.Headers.TryAddWithoutValidation(AlreadyRetried, "1");

        return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<HttpRequestMessage> CloneAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy,
        };

        if (request.Content is not null)
        {
            var buffer = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
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
