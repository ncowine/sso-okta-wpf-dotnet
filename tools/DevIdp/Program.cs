using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DevIdp;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

// ─────────────────────────────────────────────────────────────────────────────
//  DevIdp — a local stand-in for Okta, so this solution runs end to end with no
//  tenant. See Model.cs for the (important) warnings. LOCAL DEVELOPMENT ONLY.
// ─────────────────────────────────────────────────────────────────────────────

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<DevIdpStore>();
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);

var app = builder.Build();
var store = app.Services.GetRequiredService<DevIdpStore>();

const string SessionCookie = "devidp_session";

string Origin(HttpRequest request) => $"{request.Scheme}://{request.Host}";

AuthServer? Server(string id) => store.AuthServers.TryGetValue(id, out var s) ? s : null;

// ── Discovery (README §D.1) ──────────────────────────────────────────────────
app.MapGet("/oauth2/{authServerId}/.well-known/openid-configuration",
    (string authServerId, HttpRequest request) =>
{
    if (Server(authServerId) is not { } authServer) return Results.NotFound();

    var issuer = authServer.Issuer(Origin(request));

    return Results.Json(new Dictionary<string, object>
    {
        ["issuer"] = issuer,
        ["authorization_endpoint"] = $"{issuer}/v1/authorize",
        ["token_endpoint"] = $"{issuer}/v1/token",
        ["userinfo_endpoint"] = $"{issuer}/v1/userinfo",
        ["jwks_uri"] = $"{issuer}/v1/keys",
        ["introspection_endpoint"] = $"{issuer}/v1/introspect",
        ["revocation_endpoint"] = $"{issuer}/v1/revoke",
        ["end_session_endpoint"] = $"{issuer}/v1/logout",
        ["response_types_supported"] = new[] { "code" },
        ["grant_types_supported"] = new[]
        {
            "authorization_code", "refresh_token", "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        },
        ["scopes_supported"] = new[] { "openid", "profile", "email", "offline_access" }
            .Concat(authServer.Scopes).ToArray(),
        ["token_endpoint_auth_methods_supported"] = new[] { "none", "private_key_jwt" },
        ["code_challenge_methods_supported"] = new[] { "S256" },
        ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
        ["subject_types_supported"] = new[] { "public" },
    });
});

// ── JWKS (README §D.9) ───────────────────────────────────────────────────────
app.MapGet("/oauth2/{authServerId}/v1/keys", (string authServerId) =>
{
    if (Server(authServerId) is null) return Results.NotFound();

    var parameters = store.SigningKey.Rsa!.ExportParameters(false);

    static string B64(byte[] b) =>
        Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    return Results.Json(new
    {
        keys = new[]
        {
            new
            {
                kty = "RSA",
                alg = "RS256",
                use = "sig",
                kid = store.SigningKey.KeyId,
                n = B64(parameters.Modulus!),
                e = B64(parameters.Exponent!),
            },
        },
    });
});

// ── /authorize (README §C.1) ─────────────────────────────────────────────────
app.MapGet("/oauth2/{authServerId}/v1/authorize", (string authServerId, HttpRequest request) =>
{
    if (Server(authServerId) is not { } authServer) return Results.NotFound();

    var q = request.Query;
    var clientId = q["client_id"].ToString();
    var redirectUri = q["redirect_uri"].ToString();
    var state = q["state"].ToString();
    var scope = q["scope"].ToString();
    var challenge = q["code_challenge"].ToString();
    var method = q["code_challenge_method"].ToString();
    var nonce = q["nonce"].ToString();
    var prompt = q["prompt"].ToString();

    if (string.IsNullOrEmpty(redirectUri)) return Results.BadRequest("redirect_uri is required");

    // PKCE is mandatory for public clients (README §4.1).
    if (string.IsNullOrEmpty(challenge) || method != "S256")
        return Redirect(redirectUri, state, error: "invalid_request",
                        description: "PKCE with code_challenge_method=S256 is required");

    // Existing session? This is the whole of cross-app SSO (README §10.1): AppB reaches
    // this point with the cookie already set and never sees a prompt.
    request.Cookies.TryGetValue(SessionCookie, out var sessionId);

    if (sessionId is not null && store.Sessions.TryGetValue(sessionId, out var sessionUserId))
        return IssueCode(sessionUserId);

    // prompt=none means "succeed silently or fail" — never surprise the user with a
    // window mid-workflow (README §8.9).
    if (prompt == "none")
        return Redirect(redirectUri, state, error: "login_required",
                        description: "No active session and prompt=none was requested");

    // No session: show the picker. A real IdP authenticates here.
    var options = string.Join("\n", store.Users.Select(u => $"""
        <li>
          <a href="?{request.QueryString.Value?.TrimStart('?')}&amp;devidp_user={u.Id}">
            <strong>{u.Name}</strong>
            <span>{u.Login}</span>
            <em>{string.Join(", ", u.Groups)}</em>
          </a>
        </li>
        """));

    var selected = q["devidp_user"].ToString();
    if (!string.IsNullOrEmpty(selected) && store.FindUser(selected) is { } picked)
    {
        var newSession = DevIdpStore.NewToken();
        store.Sessions[newSession] = picked.Id;

        // Persistent, mirroring the Okta setting that decides whether desktop SSO
        // survives a browser restart (README §10.1).
        request.HttpContext.Response.Cookies.Append(SessionCookie, newSession, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTimeOffset.UtcNow.AddHours(8),
        });

        return IssueCode(picked.Id);
    }

    return Results.Content($$"""
        <!doctype html><html><head><meta charset="utf-8"><title>DevIdp — sign in</title>
        <style>
          body{font-family:Segoe UI,system-ui,sans-serif;background:#fafafa;color:#1a1a1a;
               display:grid;place-items:center;height:100vh;margin:0}
          .c{background:#fff;border:1px solid #e0e0e0;border-radius:10px;padding:28px 32px;
             min-width:380px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
          h1{font-size:1.1rem;margin:0 0 4px}
          p.sub{color:#666;font-size:.82rem;margin:0 0 18px}
          ul{list-style:none;padding:0;margin:0}
          li a{display:block;padding:12px 14px;border:1px solid #e0e0e0;border-radius:8px;
               margin-bottom:8px;text-decoration:none;color:inherit}
          li a:hover{border-color:#0f62fe;background:#f5f8ff}
          strong{display:block;font-size:.95rem}
          span{display:block;color:#666;font-size:.8rem}
          em{display:block;color:#0f62fe;font-size:.72rem;font-style:normal;margin-top:4px}
          .warn{margin-top:18px;padding:10px 12px;background:#fff8e1;border:1px solid #ffe082;
                border-radius:6px;font-size:.75rem;color:#7a5900}
        </style></head><body><div class="c">
        <h1>DevIdp</h1>
        <p class="sub">Local stand-in for Okta &middot; <code>{{authServer.Id}}</code> &middot; client <code>{{clientId}}</code></p>
        <ul>{{options}}</ul>
        <div class="warn">No credentials are checked. Development only.</div>
        </div></body></html>
        """, "text/html");

    IResult IssueCode(string userId)
    {
        var code = DevIdpStore.NewToken();

        store.Codes[code] = new PendingCode(
            clientId, redirectUri, challenge, scope, userId, authServerId,
            string.IsNullOrEmpty(nonce) ? null : nonce,
            DateTimeOffset.UtcNow.AddMinutes(1));

        return Redirect(redirectUri, state, code: code);
    }
});

static IResult Redirect(string redirectUri, string state,
    string? code = null, string? error = null, string? description = null)
{
    var separator = redirectUri.Contains('?') ? "&" : "?";
    var query = new List<string>();

    if (code is not null) query.Add($"code={Uri.EscapeDataString(code)}");
    if (error is not null) query.Add($"error={Uri.EscapeDataString(error)}");
    if (description is not null) query.Add($"error_description={Uri.EscapeDataString(description)}");
    if (!string.IsNullOrEmpty(state)) query.Add($"state={Uri.EscapeDataString(state)}");

    return Results.Redirect($"{redirectUri}{separator}{string.Join("&", query)}");
}

// ── /token (README §C.3–C.6) ─────────────────────────────────────────────────
app.MapPost("/oauth2/{authServerId}/v1/token",
    async (string authServerId, HttpRequest request) =>
{
    if (Server(authServerId) is not { } authServer) return Results.NotFound();

    store.Sweep();

    var form = await request.ReadFormAsync();
    var grantType = form["grant_type"].ToString();
    var clientId = form["client_id"].ToString();
    var origin = Origin(request);

    static IResult OAuthError(string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: 400);

    switch (grantType)
    {
        case "authorization_code":
        {
            var code = form["code"].ToString();
            var verifier = form["code_verifier"].ToString();
            var redirectUri = form["redirect_uri"].ToString();

            if (!store.Codes.TryRemove(code, out var pending))
                return OAuthError("invalid_grant", "Authorization code is invalid, expired, or already used.");

            if (pending.Expires < DateTimeOffset.UtcNow)
                return OAuthError("invalid_grant", "Authorization code has expired.");

            // redirect_uri must be byte-identical to the one sent to /authorize — a
            // common source of invalid_grant (README §C.3).
            if (!string.Equals(pending.RedirectUri, redirectUri, StringComparison.Ordinal))
                return OAuthError("invalid_grant", "redirect_uri does not match the authorization request.");

            // PKCE verification (README §4.1).
            var computed = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');

            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(computed), Encoding.ASCII.GetBytes(pending.CodeChallenge)))
                return OAuthError("invalid_grant", "PKCE verification failed.");

            if (store.FindUser(pending.UserId) is not { } user)
                return OAuthError("invalid_grant", "User no longer exists.");

            return TokenResponse(authServer, origin, user, clientId, pending.Scope,
                                 pending.Nonce, issueRefresh: pending.Scope.Contains("offline_access"));
        }

        case "refresh_token":
        {
            var refreshToken = form["refresh_token"].ToString();

            if (!store.RefreshTokens.TryRemove(refreshToken, out var grant))
                return OAuthError("invalid_grant", "Refresh token is invalid, expired, or has been rotated.");

            if (grant.Expires < DateTimeOffset.UtcNow)
                return OAuthError("invalid_grant", "Refresh token has expired.");

            if (store.FindUser(grant.UserId) is not { } user)
                return OAuthError("invalid_grant", "User no longer exists.");

            // Rotation: the old token was just removed, so replaying it fails. That is
            // the theft-detection property in README §5.6.
            var scope = string.IsNullOrEmpty(form["scope"].ToString()) ? grant.Scope : form["scope"].ToString();

            return TokenResponse(authServer, origin, user, grant.ClientId, scope,
                                 nonce: null, issueRefresh: true);
        }

        case "client_credentials":
        {
            // No user. The resulting token has 'cid' and no 'uid' (README §7.2).
            var scope = form["scope"].ToString();

            return Results.Json(new
            {
                token_type = "Bearer",
                expires_in = (int)Tokens.AccessTokenLifetime.TotalSeconds,
                access_token = Tokens.AccessToken(store, authServer, origin, null, clientId, Split(scope)),
                scope,
            });
        }

        case "urn:ietf:params:oauth:grant-type:token-exchange":
        {
            // README §7.1 — On-Behalf-Of.
            var subjectToken = form["subject_token"].ToString();
            var audience = form["audience"].ToString();
            var scope = form["scope"].ToString();

            if (Tokens.TryRead(subjectToken) is not { } subject)
                return OAuthError("invalid_request", "subject_token is not a readable JWT.");

            if (subject.ValidTo < DateTime.UtcNow)
                return OAuthError("invalid_grant", "subject_token has expired.");

            // The subject token must come from a server this one trusts — Okta's trusted
            // server relationship (README §5.7).
            var subjectIssuer = subject.Issuer;
            var trusted = authServer.TrustedServers
                .Append(authServer.Id)
                .Any(id => subjectIssuer.EndsWith($"/oauth2/{id}", StringComparison.Ordinal));

            if (!trusted)
                return OAuthError("invalid_grant",
                    $"The issuer of subject_token ({subjectIssuer}) is not a trusted server of {authServer.Id}.");

            if (!string.Equals(audience, authServer.Audience, StringComparison.Ordinal))
                return OAuthError("invalid_request",
                    $"This authorization server only issues tokens for {authServer.Audience}.");

            var uid = subject.GetClaim("uid")?.Value;
            if (uid is null || store.FindUser(uid) is not { } exchangeUser)
            {
                return OAuthError("invalid_grant",
                    "subject_token has no user. Token exchange preserves a user's identity; " +
                    "for service-to-service work with no user, use client_credentials.");
            }

            // Policy is re-evaluated here, which is exactly what makes Pattern 1 stronger
            // than forwarding: a deprovisioned user fails at this point.
            return Results.Json(new
            {
                token_type = "Bearer",
                expires_in = (int)Tokens.AccessTokenLifetime.TotalSeconds,
                access_token = Tokens.AccessToken(
                    store, authServer, origin, exchangeUser, clientId, Split(scope)),
                scope,
                issued_token_type = "urn:ietf:params:oauth:token-type:access_token",
            });
        }

        default:
            return OAuthError("unsupported_grant_type", $"'{grantType}' is not supported by DevIdp.");
    }

    IResult TokenResponse(
        AuthServer authServer, string origin, DevUser user, string clientId,
        string scope, string? nonce, bool issueRefresh)
    {
        var scopes = Split(scope);
        string? refreshToken = null;

        if (issueRefresh)
        {
            refreshToken = DevIdpStore.NewToken();
            store.RefreshTokens[refreshToken] = new RefreshGrant(
                clientId, user.Id, scope, authServer.Id,
                DateTimeOffset.UtcNow.Add(Tokens.RefreshTokenLifetime));
        }

        var body = new Dictionary<string, object?>
        {
            ["token_type"] = "Bearer",
            ["expires_in"] = (int)Tokens.AccessTokenLifetime.TotalSeconds,
            ["access_token"] = Tokens.AccessToken(store, authServer, origin, user, clientId, scopes),
            ["scope"] = scope,
        };

        if (scopes.Contains("openid"))
            body["id_token"] = Tokens.IdToken(store, authServer, origin, user, clientId, nonce);

        if (refreshToken is not null) body["refresh_token"] = refreshToken;

        return Results.Json(body);
    }

    static string[] Split(string scope) =>
        scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
});

// ── /introspect (README §D.7) ────────────────────────────────────────────────
app.MapPost("/oauth2/{authServerId}/v1/introspect", async (string authServerId, HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var token = form["token"].ToString();
    var jwt = Tokens.TryRead(token);

    // Note the shape: an invalid token returns HTTP 200 with active:false, never an
    // error status. Code that checks only the status code treats it as valid.
    if (jwt is null || jwt.ValidTo < DateTime.UtcNow)
        return Results.Json(new { active = false });

    return Results.Json(new
    {
        active = true,
        scope = string.Join(' ', jwt.Claims.Where(c => c.Type == "scp").Select(c => c.Value)),
        sub = jwt.GetClaim("sub")?.Value,
        aud = jwt.Audiences.FirstOrDefault(),
        iss = jwt.Issuer,
        jti = jwt.GetClaim("jti")?.Value,
        client_id = jwt.GetClaim("cid")?.Value,
        uid = jwt.Claims.FirstOrDefault(c => c.Type == "uid")?.Value,
        token_type = "Bearer",
        exp = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds(),
    });
});

// ── /revoke (README §D.10) ───────────────────────────────────────────────────
app.MapPost("/oauth2/{authServerId}/v1/revoke", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    store.RefreshTokens.TryRemove(form["token"].ToString(), out _);

    // RFC 7009: always 200, even for a token that never existed, so the endpoint cannot
    // be used to probe which tokens are real.
    return Results.Ok();
});

// ── /logout — RP-initiated (README §11.2) ────────────────────────────────────
app.MapGet("/oauth2/{authServerId}/v1/logout", (HttpRequest request) =>
{
    if (request.Cookies.TryGetValue(SessionCookie, out var sessionId) && sessionId is not null)
    {
        store.Sessions.TryRemove(sessionId, out _);
        request.HttpContext.Response.Cookies.Delete(SessionCookie);
    }

    var postLogout = request.Query["post_logout_redirect_uri"].ToString();

    return string.IsNullOrEmpty(postLogout)
        ? Results.Content("<h1>Signed out of DevIdp</h1>", "text/html")
        : Results.Redirect(postLogout);
});

app.MapGet("/", (HttpRequest request) => Results.Content($$"""
    <!doctype html><html><head><meta charset="utf-8"><title>DevIdp</title>
    <style>body{font-family:Segoe UI,system-ui,sans-serif;max-width:760px;margin:60px auto;
    color:#1a1a1a;line-height:1.6}code{background:#f2f2f2;padding:1px 5px;border-radius:3px}
    .warn{padding:12px 14px;background:#fff8e1;border:1px solid #ffe082;border-radius:6px}</style>
    </head><body>
    <h1>DevIdp</h1>
    <p>A local stand-in for Okta, so this solution runs end to end without a tenant.</p>
    <div class="warn"><strong>Development only.</strong> It authenticates nobody and signs
    with a key generated at startup. Never deploy it.</div>
    <h2>Authorization servers</h2>
    <ul>
      <li><code>apia-as</code> &rarr; <code>api://apia</code> &middot;
        <a href="/oauth2/apia-as/.well-known/openid-configuration">metadata</a></li>
      <li><code>apib-as</code> &rarr; <code>api://apib</code> &middot;
        <a href="/oauth2/apib-as/.well-known/openid-configuration">metadata</a></li>
    </ul>
    <h2>Users</h2>
    <ul>
      <li><code>alice@contoso.com</code> — App-Finance, App-Warehouse (sees everything)</li>
      <li><code>bob@contoso.com</code> — App-Warehouse only (ApiB returns 403, by design)</li>
    </ul>
    <p><a href="/oauth2/apia-as/v1/logout">Sign out</a> to reset the SSO session.</p>
    </body></html>
    """, "text/html"));

app.Run();

public partial class Program;
