extern alias ApiAHost;
extern alias ApiBHost;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DevIdp;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Corp.Api.Security.Tests;

/// <summary>
/// The real thing: DevIdp issues tokens, ApiA validates one and delegates to ApiB, and
/// ApiB validates the delegated token and enforces its own authorization.
/// </summary>
/// <remarks>
/// <para>This is what README §15.4 describes as an integration test, run against the local
/// DevIdp rather than a live Okta tenant so it needs no credentials and always runs.
/// The protocol is the same; only the issuer differs.</para>
/// <para>All three hosts run in-process and are wired to each other with
/// <see cref="HttpClient"/> instances backed by their respective test servers, so no
/// ports are bound and the suite is safe to run in parallel with anything else.</para>
/// </remarks>
public sealed class EndToEndDelegationTests : IAsyncLifetime
{
    private WebApplicationFactory<Program>? _idp;
    private WebApplicationFactory<ApiAHost::Program>? _apiA;
    private WebApplicationFactory<ApiBHost::Program>? _apiB;

    private HttpClient _idpClient = null!;
    private HttpClient _apiAClient = null!;

    private const string IdpOrigin = "http://localhost";

    public Task InitializeAsync()
    {
        _idp = new WebApplicationFactory<Program>();
        _idpClient = _idp.CreateClient();

        // The two APIs point at each other, so the downstream client is resolved lazily:
        // ApiB's handler asks for ApiA's client only when a request is actually made,
        // by which time both factories exist. This is what lets the cycle test in
        // A_delegation_cycle_is_stopped_by_the_depth_guard exercise a REAL cycle.
        HttpClient? apiAClientForB = null;

        _apiB = new ApiFactoryFor<ApiBHost::Program>(
            issuer: $"{IdpOrigin}/oauth2/apib-as",
            audience: "api://apib",
            serviceClientId: "apib-service",
            downstreamName: "ApiA",
            downstreamAudience: "api://apia",
            downstreamScopes: "apia.read",
            downstreamIssuer: $"{IdpOrigin}/oauth2/apia-as",
            idpClient: _idpClient,
            downstreamClient: () => apiAClientForB);

        var apiBClient = _apiB.CreateClient();

        _apiA = new ApiFactoryFor<ApiAHost::Program>(
            issuer: $"{IdpOrigin}/oauth2/apia-as",
            audience: "api://apia",
            serviceClientId: "apia-service",
            downstreamName: "ApiB",
            downstreamAudience: "api://apib",
            downstreamScopes: "apib.read",
            downstreamIssuer: $"{IdpOrigin}/oauth2/apib-as",
            idpClient: _idpClient,
            downstreamClient: () => apiBClient);

        _apiAClient = _apiA.CreateClient();
        apiAClientForB = _apiA.CreateClient();

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_apiA is not null) await _apiA.DisposeAsync();
        if (_apiB is not null) await _apiB.DisposeAsync();
        if (_idp is not null) await _idp.DisposeAsync();
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_user_token_from_the_idp_is_accepted_by_ApiA()
    {
        var token = await SignInAsync("00udevalice", "apia-as", "openid apia.read apia.write");

        var body = await GetJsonAsync("orders/whoami", token);

        Assert.Equal("ApiA", body.GetProperty("api").GetString());
        Assert.Equal("alice@contoso.com", body.GetProperty("subject").GetString());
        Assert.False(body.GetProperty("isServicePrincipal").GetBoolean());
    }

    [Fact]
    public async Task On_behalf_of_delegation_preserves_the_user_and_records_the_actor()
    {
        // The core claim of README §7.1, proven end to end.
        var token = await SignInAsync("00udevalice", "apia-as", "openid apia.read");

        var body = await GetJsonAsync(
            "orders/22222222-2222-2222-2222-222222222222/billing", token);

        var invoice = body.GetProperty("invoice");

        Assert.Equal("alice@contoso.com", invoice.GetProperty("servedTo").GetString());
        Assert.Equal("ApiB", invoice.GetProperty("servedBy").GetString());
    }

    [Fact]
    public async Task ApiB_enforces_its_own_authorization_rather_than_trusting_ApiA()
    {
        // Bob is in App-Warehouse only. ApiA is happy to make the call; ApiB refuses,
        // because the delegated token carries BOB's groups, not ApiA's opinion of them.
        // This is precisely what forwarding ApiA's own token would have destroyed.
        var token = await SignInAsync("00udevbob", "apia-as", "openid apia.read");

        var response = await SendAsync(
            "orders/22222222-2222-2222-2222-222222222222/billing", token);

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(403, body.GetProperty("downstreamStatus").GetInt32());
    }

    [Fact]
    public async Task A_service_identity_call_carries_no_user()
    {
        var token = await SignInAsync("00udevalice", "apia-as", "openid apia.read");

        var body = await GetJsonAsync("orders/reconcile", token);

        Assert.Equal("service identity", body.GetProperty("calledAs").GetString());
        Assert.Contains("service:apia-service",
            body.GetProperty("downstream").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_delegation_cycle_is_stopped_by_the_depth_guard()
    {
        // ApiA -> ApiB -> ApiA -> … Every hop is individually valid; the guard is what
        // stops it (README §7.7). The request must terminate, not hang or recurse.
        var token = await SignInAsync("00udevalice", "apia-as", "openid apia.read");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var response = await SendAsync("orders/cycle-demo", token, cts.Token);

        // Either the outermost call reports the downstream failure, or it surfaces as
        // 508 directly. What must NOT happen is an unbounded recursion.
        Assert.True(
            response.StatusCode is HttpStatusCode.OK or HttpStatusCode.LoopDetected
                or HttpStatusCode.BadGateway,
            $"Unexpected status {(int)response.StatusCode}");

        var text = await response.Content.ReadAsStringAsync();
        Assert.Contains("508", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Group_filtering_reflects_the_signed_in_user()
    {
        var alice = await SignInAsync("00udevalice", "apia-as", "openid apia.read");
        var bob = await SignInAsync("00udevbob", "apia-as", "openid apia.read");

        var aliceOrders = await GetStringAsync("orders", alice);
        var bobOrders = await GetStringAsync("orders", bob);

        // Alice is in both groups; Bob only in App-Warehouse.
        Assert.Contains("Consulting retainer", aliceOrders, StringComparison.Ordinal);
        Assert.DoesNotContain("Consulting retainer", bobOrders, StringComparison.Ordinal);
        Assert.Contains("Widget assembly", bobOrders, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_token_for_ApiB_is_rejected_by_ApiA()
    {
        // Rule 1 (README §3.3), proven against real IdP-issued tokens.
        var token = await SignInAsync("00udevalice", "apib-as", "openid apib.read");

        var response = await SendAsync("orders/whoami", token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>Runs a full authorization-code + PKCE flow against DevIdp.</summary>
    private async Task<string> SignInAsync(string userId, string authServer, string scope)
    {
        var verifier = DevIdpStore.NewToken();
        var challenge = Pkce.Challenge(verifier);
        const string redirect = "http://127.0.0.1:8765/callback";

        var authorizeUrl =
            $"/oauth2/{authServer}/v1/authorize" +
            $"?client_id=test-client&response_type=code" +
            $"&scope={Uri.EscapeDataString(scope + " offline_access")}" +
            $"&redirect_uri={Uri.EscapeDataString(redirect)}" +
            $"&state=st&code_challenge={challenge}&code_challenge_method=S256" +
            $"&devidp_user={userId}";

        using var handler = _idp!.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        using var authorizeResponse = await handler.GetAsync(authorizeUrl);
        var location = authorizeResponse.Headers.Location
            ?? throw new InvalidOperationException(
                $"DevIdp did not redirect: {(int)authorizeResponse.StatusCode}");

        var code = System.Web.HttpUtility.ParseQueryString(location.Query)["code"]
            ?? throw new InvalidOperationException($"No code in redirect: {location}");

        using var tokenResponse = await _idpClient.PostAsync(
            $"/oauth2/{authServer}/v1/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["code_verifier"] = verifier,
                ["redirect_uri"] = redirect,
                ["client_id"] = "test-client",
            }));

        tokenResponse.EnsureSuccessStatusCode();

        var payload = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        return payload.GetProperty("access_token").GetString()!;
    }

    private Task<HttpResponseMessage> SendAsync(
        string path, string token, CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return _apiAClient.SendAsync(request, ct);
    }

    private async Task<JsonElement> GetJsonAsync(string path, string token)
    {
        using var response = await SendAsync(path, token);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private async Task<string> GetStringAsync(string path, string token)
    {
        using var response = await SendAsync(path, token);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }
}

internal static class Pkce
{
    public static string Challenge(string verifier) =>
        Convert.ToBase64String(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.ASCII.GetBytes(verifier)))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
}

/// <summary>
/// Hosts one API wired to the in-process DevIdp and, optionally, to a downstream API.
/// </summary>
internal sealed class ApiFactoryFor<TEntryPoint>(
    string issuer,
    string audience,
    string serviceClientId,
    string downstreamName,
    string downstreamAudience,
    string downstreamScopes,
    string downstreamIssuer,
    HttpClient idpClient,
    Func<HttpClient?> downstreamClient) : WebApplicationFactory<TEntryPoint>
    where TEntryPoint : class
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Production"); // avoid the Development overrides

        builder.ConfigureHostConfiguration(config => config.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Delegation:Pattern"] = "OnBehalfOf",
                ["Okta:Issuer"] = issuer,
                ["Okta:Audience"] = audience,
                ["Okta:Service:ClientId"] = serviceClientId,
                ["Okta:Service:SigningCertificateThumbprint"] = "", // DevIdp needs no client auth
                [$"Okta:Downstream:{downstreamName}:BaseAddress"] = "http://downstream.local/",
                [$"Okta:Downstream:{downstreamName}:Audience"] = downstreamAudience,
                [$"Okta:Downstream:{downstreamName}:Scopes"] = downstreamScopes,
                [$"Okta:Downstream:{downstreamName}:Issuer"] = downstreamIssuer,
            }));

        builder.ConfigureServices(services =>
        {
            // Point token validation, token acquisition, and the downstream call at the
            // in-process hosts instead of the network.
            services.AddSingleton<IHttpMessageHandlerBuilderFilterStub>(
                new IHttpMessageHandlerBuilderFilterStub());

            services.ConfigureAll<Microsoft.Extensions.Http.HttpClientFactoryOptions>(options =>
                options.HttpMessageHandlerBuilderActions.Add(b =>
                {
                    if (b.Name == downstreamName && downstreamClient() is { } dc1)
                        b.PrimaryHandler = new RedirectingHandler(dc1);
                    else if (b.Name.Contains("OktaTokenService", StringComparison.Ordinal) ||
                             b.Name.Contains("IOktaTokenService", StringComparison.Ordinal))
                        b.PrimaryHandler = new RedirectingHandler(idpClient);
                    else if (b.Name.StartsWith(downstreamName, StringComparison.Ordinal) &&
                             downstreamClient() is { } dc2)
                        b.PrimaryHandler = new RedirectingHandler(dc2);
                }));

            // Configure, not PostConfigure: the framework's own post-configure validates
            // RequireHttpsMetadata and would throw before ours ever ran.
            services.Configure<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>(
                Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme,
                options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.BackchannelHttpHandler = new RedirectingHandler(idpClient);
                });
        });

        return base.CreateHost(builder);
    }

    internal sealed class IHttpMessageHandlerBuilderFilterStub;

    /// <summary>Sends a request to another in-process test server instead of the network.</summary>
    private sealed class RedirectingHandler(HttpClient target) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var rewritten = new HttpRequestMessage(request.Method,
                new Uri(target.BaseAddress!, request.RequestUri!.PathAndQuery));

            foreach (var header in request.Headers)
                rewritten.Headers.TryAddWithoutValidation(header.Key, header.Value);

            if (request.Content is not null)
            {
                var bytes = await request.Content.ReadAsByteArrayAsync(cancellationToken);
                rewritten.Content = new ByteArrayContent(bytes);

                foreach (var header in request.Content.Headers)
                    rewritten.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return await target.SendAsync(rewritten, cancellationToken);
        }
    }
}
