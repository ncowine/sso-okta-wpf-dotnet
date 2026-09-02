# Enterprise SSO with Okta — A Production Guide for .NET 8 WPF + ASP.NET Core

**Reference architecture:** two Prism/Telerik WPF desktop clients (`AppA`, `AppB`), two ASP.NET Core APIs (`ApiA`, `ApiB`) that call each other, one Okta tenant.

| | |
|---|---|
| **Identity Provider** | Okta (Identity Engine), Custom Authorization Server |
| **Desktop clients** | .NET 8 · WPF · Prism 8 (DryIoc) · Telerik UI for WPF |
| **Services** | .NET 8 · ASP.NET Core · hosted on IIS (Windows) |
| **User sign-in** | OAuth 2.0 Authorization Code + PKCE, system browser, loopback redirect |
| **Cross-app SSO** | Okta browser session (primary) · Okta Native SSO (Appendix A) |
| **Service-to-service** | Four documented patterns, §7 — pick one before building |
| **Status** | Specification. The runnable demo is in [DEMO.md](DEMO.md). |

---

> **New to OAuth and OpenID Connect?** Start with [GUIDE.md](GUIDE.md) — a ground-up walkthrough
> that builds the mental model, gets the demo running, and explains why each decision was made.
> This document is the reference specification; the guide is the way in.

## Table of contents

**Part I — Understand**

1. [How to read this document](#1-how-to-read-this-document)
2. [The problem SSO actually solves](#2-the-problem-sso-actually-solves)
3. [Protocol foundations](#3-protocol-foundations)
4. [Design decisions and rejected alternatives](#4-design-decisions-and-rejected-alternatives)

**Part II — Configure**

5. [Okta tenant design](#5-okta-tenant-design)
6. [Okta configuration walkthrough](#6-okta-configuration-walkthrough)

**Part III — Build**

7. [ApiA ↔ ApiB: the four delegation patterns](#7-apia--apib-the-four-delegation-patterns)
8. [The WPF client](#8-the-wpf-client)
9. [The ASP.NET Core APIs](#9-the-aspnet-core-apis)
10. [Cross-app SSO between AppA and AppB](#10-cross-app-sso-between-appa-and-appb)
11. [Sign-out and session termination](#11-sign-out-and-session-termination)

**Part IV — Operate**

12. [Security hardening and threat model](#12-security-hardening-and-threat-model)
13. [Deployment on IIS](#13-deployment-on-iis)
14. [Observability and troubleshooting](#14-observability-and-troubleshooting)
15. [Testing strategy](#15-testing-strategy)
16. [Go-live checklist](#16-go-live-checklist)

**Appendices**

- [A. Okta Native SSO](#appendix-a--okta-native-sso)
- [B. Configuration reference sheet](#appendix-b--configuration-reference-sheet)
- [C. Raw HTTP transcripts](#appendix-c--raw-http-transcripts)
- [D. Okta response reference](#appendix-d--okta-response-reference) — every response shape, annotated
- [E. What to store, where, and what must never be shared](#appendix-e--what-to-store-where-and-what-must-never-be-shared)
- [F. Do's and don'ts](#appendix-f--dos-and-donts) — the consolidated review card
- [G. Glossary](#appendix-g--glossary)
- [H. References](#appendix-h--references)

> **In a hurry?** [Appendix F](#appendix-f--dos-and-donts) is the whole document compressed into do/don't rows, each linked to the section that explains it. [Appendix E](#appendix-e--what-to-store-where-and-what-must-never-be-shared) answers "what do we store and what must never cross this boundary". [Appendix D](#appendix-d--okta-response-reference) is the field-by-field response reference.

---

# Part I — Understand

## 1. How to read this document

Read Part I once, in order. It is short, and everything later depends on it. Parts II–IV are reference material — configure from Part II, build from Part III, operate from Part IV.

Conventions used throughout:

- `{yourOktaDomain}` — e.g. `dev-12345678.okta.com`, or `login.contoso.com` if you use an Okta custom domain.
- `{authServerId}` — the ID of a Custom Authorization Server, e.g. `aus1a2b3c4d5e6f7g8h9`. The built-in one has the literal ID `default`.
- Placeholders you must fill in are collected in [Appendix B](#appendix-b--configuration-reference-sheet). Fill that in first; the rest of the document refers to it.

> ⚠️ **Callouts marked like this are load-bearing.** They mark places where the obvious implementation is insecure, or where Okta's behaviour differs from the generic OAuth 2.0 you may have read elsewhere.

---

## 2. The problem SSO actually solves

The common framing — "one password for everything" — is wrong, and it leads to bad architecture. The accurate framing is:

> **SSO means your applications stop verifying credentials.** Exactly one system ever sees a password, a passkey, or an MFA factor. Everything else consumes cryptographically signed *assertions* about who the user is and what they may do.

Without SSO, `AppA` and `AppB` each need a user store, a password policy, a lockout mechanism, an MFA implementation, a password-reset flow, and a deprovisioning story. That is five security-critical subsystems duplicated per application, each an independent opportunity to get it wrong, and no single place to disable a departing employee.

With SSO, Okta owns all of that. `ApiA` and `ApiB` own one thing: **signature verification**.

### 2.1 What "single sign-on" means concretely for a desktop estate

A user launches `AppA` in the morning and signs in. They launch `AppB` at lunchtime and are **not prompted**.

That second part is not automatic. It is a mechanism you must deliberately choose and configure. On Windows there are exactly three ways to get it, covered in [§10](#10-cross-app-sso-between-appa-and-appb):

1. The **Okta session cookie** in the system browser — chosen as primary for this architecture.
2. **Okta Native SSO** — a device secret exchanged directly between the two apps, no browser involved ([Appendix A](#appendix-a--okta-native-sso)).
3. **Okta Desktop SSO / Okta Verify** — the Windows/AD logon session itself, for a genuinely zero-prompt experience.

> ⚠️ **SSO is a shared *session at the IdP*. It is not shared *credentials between apps*.**
> `AppA` and `AppB` get **separate `client_id`s** and **separate tokens**. Sharing one `client_id` across two applications destroys your ability to revoke one, scope one differently, tell them apart in the Okta System Log, or apply different sign-on policies. It is never the right answer.

### 2.2 The trust topology

```
                    ┌───────────────────────────────────────────────┐
                    │                    OKTA                       │
                    │  ┌─────────────────────────────────────────┐  │
   Universal        │  │  Custom Authorization Server            │  │
   Directory  ─────►│  │  issuer: https://{domain}/oauth2/{id}   │  │
   (users,          │  │  · signs tokens (RS256, private key)    │  │
    groups)         │  │  · publishes public keys at /v1/keys    │  │
                    │  │  · owns scopes, claims, policies        │  │
                    │  └─────────────────────────────────────────┘  │
                    │  Session cookie ── the SSO mechanism ─────────│
                    └───────────────────────────────────────────────┘
                          ▲                              ▲
             (1) PKCE via │                  (3) fetch public keys │
             system       │                      once, cache,      │
             browser      │                      validate offline  │
                          │                                        │
   ┌──────────────┐  ┌────┴─────────┐              ┌───────────────┴──┐
   │  AppB (WPF)  │  │  AppA (WPF)  │──(2) Bearer─►│  ApiA            │
   │  client_id B │  │  client_id A │  aud=api://  │  validates aud,  │
   └──────┬───────┘  └──────────────┘      apia    │  iss, sig, scp   │
          │                                        └────────┬─────────┘
          │ Bearer                                          │ (4) §7:
          │ aud=api://apib                                  │  delegation
          ▼                                                 ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  ApiB   — validates aud=api://apib, iss, signature, scopes       │
   └──────────────────────────────────────────────────────────────────┘

   Trust flows one way: Okta signs, everyone else verifies.
   No application ever calls Okta to validate a token on the request path.
```

Two properties of this diagram matter:

- **Arrow (3) happens rarely.** Each API fetches Okta's public keys at startup and caches them. Token validation is a local signature check — no network call, no latency, no availability coupling to Okta on the request path. If Okta has an outage, already-issued tokens keep working until they expire; only *new* sign-ins fail.
- **Arrow (4) is the hard part.** Everything else is well-trodden. `ApiA` calling `ApiB` is where architectures quietly become insecure, which is why it gets its own section with four fully-worked options.

---

## 3. Protocol foundations

### 3.1 Two questions, two protocols

These get conflated constantly, and keeping them separate is most of the battle.

| Question | Protocol | Artifact | Consumed by |
|---|---|---|---|
| **Who are you?** (authentication) | OpenID Connect | **ID token** | The client app (`AppA`) |
| **What may this caller do to *this* API?** (authorization) | OAuth 2.0 | **Access token** | One specific API (`ApiA`) |

OpenID Connect is a thin identity layer on top of OAuth 2.0 — one system, not two competing ones ([OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)).

SAML is the older enterprise equivalent. Okta supports it, and you will meet it when integrating third-party SaaS. For greenfield native apps talking to your own APIs it is the wrong tool: no native-app profile, no PKCE, no refresh semantics, no concept of a scoped API access token. **Use OIDC/OAuth 2.0 and nothing else here.**

### 3.2 The three tokens

**ID token** — a JWT whose `aud` is your WPF app's `client_id`. It asserts *that a login event happened*: the user's `sub`, name, email, when they authenticated (`auth_time`), and how they proved it (`amr` — password? MFA? phishing-resistant?). It is a **receipt**, not a permission.

> ⚠️ **Never send an ID token to an API, and never let an API accept one.**
> An API that accepts ID tokens cannot know whether the caller was authorised to reach it — the token was addressed to the *client*, not to the API. This is among the most common serious defects in hand-rolled SSO integrations. The explicit audience validation in §9.2 is what prevents it.

**Access token** — a JWT whose `aud` is one specific API (`api://apia`). This is the credential the API authorises against.

> ⚠️ **The client must treat the access token as opaque.** `AppA` must never decode it to make decisions — not to read roles, not to check expiry, not to display a username. Okta explicitly reserves the right to change access token structure; only the resource server it is addressed to should parse it. Use the **ID token** for UI identity, and the **`expires_in`** field of the token response for refresh scheduling.

**Refresh token** — long-lived, high-value, opaque. Lets the app obtain new access tokens with no user interaction. Okta issues one when you request the `offline_access` scope. Must be encrypted at rest and **rotated** on every use (§8.6).

### 3.3 The audience rule

Almost every serious SSO defect is a violation of one of two rules:

> ### Rule 1 — Never accept a token whose `aud` is not you.
> ### Rule 2 — Never send a token to a party that is not its `aud`.

Rule 2 is the one teams break, because breaking it is *convenient*: `ApiA` already holds the user's token, `ApiB` needs to know who the user is, so `ApiA` just forwards it. Now `ApiB` holds a credential that is **valid at `ApiA`** and can replay it, and `ApiB` cannot tell whether `ApiA` was actually permitted to make this call on the user's behalf. That is the **confused deputy** problem, and it is the entire subject of [§7](#7-apia--apib-the-four-delegation-patterns).

### 3.4 Anatomy of an Okta access token

A representative decoded payload from a Custom Authorization Server. Knowing these claims by name makes §9 and §14 far easier:

```json
{
  "ver": 1,
  "jti": "AT.xY3k9...",
  "iss": "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
  "aud": "api://apia",
  "sub": "alice@contoso.com",
  "iat": 1735689600,
  "exp": 1735690500,
  "cid": "0oa1a2b3c4d5e6f7g8h9",
  "uid": "00u1a2b3c4d5e6f7g8h9",
  "scp": ["openid", "profile", "offline_access", "apia.read", "apia.write"],
  "auth_time": 1735689598,
  "groups": ["Finance", "Warehouse"]
}
```

| Claim | Meaning | Used for |
|---|---|---|
| `iss` | The Custom AS that issued it | Validation — must match exactly |
| `aud` | Target API | Validation — **Rule 1** |
| `sub` | The user | Audit, user-level authorization |
| `cid` | The **client** that requested it | Which app is calling — useful in audit |
| `uid` | Okta user ID (stable) | Preferred join key; `sub` can change if email changes |
| `scp` | Granted scopes, **JSON array** | Endpoint-level authorization |
| `groups` | Group memberships (if claim configured) | Role-based authorization |
| `auth_time` | When the user actually authenticated | Step-up / re-auth decisions |

> ⚠️ **`scp` is a JSON array in Okta, not a space-delimited string.** Many OAuth guides (and much sample code) assume `scope` as a single space-delimited string, which is the convention some other IdPs use. In .NET, an array claim surfaces as *multiple* `scp` claims on the `ClaimsPrincipal`. §9.3 handles both shapes so the code survives an IdP migration.

> ⚠️ **Prefer `uid` over `sub` as your database foreign key.** Okta's `sub` for a Custom AS defaults to the user's login (email), which changes when someone marries, is rebranded, or moves domain. `uid` is the immutable Okta user ID.

### 3.5 Okta's vocabulary

Okta uses its own names for standard concepts. This mapping prevents a lot of confusion:

| Standard OAuth 2.0 / OIDC term | Okta calls it | Notes |
|---|---|---|
| Authorization Server | **Authorization Server** (Org or Custom) | Critical distinction — §5.1 |
| Client | **Application** / **App Integration** | Created via the App Integration Wizard |
| Public client | **Native Application** app type | No secret; PKCE mandatory |
| Confidential client (machine) | **API Services** app type | `client_credentials` only |
| Resource server / API | *(no first-class object)* | Represented by an **audience** on a Custom AS |
| Scope | **Scope** | Defined per authorization server |
| Client authentication | **Client authentication** | `none`, `client_secret_*`, or `private_key_jwt` |
| Token issuance rules | **Access Policies** → **Rules** | Governs which scopes are granted and token lifetimes |
| Who may use the app at all | **Assignments** | Independent of policy — both gates must pass |
| Audit log | **System Log** | Your primary diagnostic tool (§14) |

> ⚠️ **Assignments and Access Policies are two independent gates.** A user who satisfies your policy rule but is not *assigned* to the app integration gets `access_denied`. A user who is assigned but matches no policy rule also gets `access_denied`. The error is identical. When debugging, always check both.

---

## 4. Design decisions and rejected alternatives

This section records *why* each choice was made, so a future maintainer does not "simplify" the design back into a vulnerability.

### 4.1 Authorization Code + PKCE — **chosen**

PKCE ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) is mandatory for native apps.

The client generates a high-entropy random `code_verifier` (43–128 characters), derives `code_challenge = BASE64URL(SHA256(code_verifier))`, and sends only the challenge to `/authorize`. When redeeming the authorization code at `/token`, it presents the original verifier. Okta recomputes the hash and rejects any mismatch.

**The attack this prevents:** on Windows, the redirect travels through the loopback interface or a registered URI scheme. A malicious local process can register a competing scheme handler, or race to bind the loopback port, and steal the authorization code. Without PKCE a stolen code is a full account compromise, because a public client has no secret with which to prove it was the legitimate requester. With PKCE the code is useless without the verifier, which never leaves the originating process's memory.

Okta sets client authentication to `none` for Native Application integrations and requires PKCE.

### 4.2 The system browser, not an embedded WebView2 — **chosen**

Mandated by [RFC 8252 §8.12](https://datatracker.ietf.org/doc/html/rfc8252#section-8.12) (*OAuth 2.0 for Native Apps*). This is not a stylistic preference. Four independent reasons:

1. **It is the SSO mechanism.** The Okta session cookie lives in the system browser's cookie jar. An embedded WebView2 has its own isolated jar, so `AppB` would prompt for credentials again — you would have built single sign-on that does not sign on singly.
2. **It is the only anti-phishing control the user has.** In the system browser the user sees the real `{yourOktaDomain}` URL and TLS padlock. An app-controlled embedded browser is pixel-identical to a credential-harvesting form, and it actively *trains users* to type their corporate password into application chrome.
3. **Modern authenticators do not work in it.** WebAuthn/passkeys, Windows Hello, smart cards, Okta FastPass, and device-trust signals depend on the real browser and its OS integration.
4. **The host application can read the credentials.** A WPF host can script an embedded WebView2's DOM. The entire security premise of delegated authentication is that the client *cannot* see the password; an embedded browser silently forfeits it.

> ⚠️ **Do not "fix" a UX complaint by moving to WebView2.** If the browser hand-off feels jarring, address it with a `RadBusyIndicator` overlay and deliberate window-focus management (§8.8) — not by abandoning the security model.

### 4.3 Loopback redirect (`http://127.0.0.1:{port}/callback`) — **chosen**

[RFC 8252 §7](https://datatracker.ietf.org/doc/html/rfc8252#section-7) defines two viable redirect options for native apps: a **loopback interface** listener, or a **private-use URI scheme** (`appa://callback`).

For a Windows desktop application, loopback wins:

- **No registry writes**, so no installer elevation. A custom scheme needs `HKCR` (machine-wide, requires admin) or `HKCU\Software\Classes` (per-user, breaks under some managed-desktop policies).
- A custom scheme is a **machine-global namespace**. Any other installed application can register `appa://` and hijack your callback, and Windows gives you no way to detect or prevent it. Loopback + PKCE + `state` is strictly stronger.
- **Debuggable.** The redirect is an ordinary HTTP request you can observe with Fiddler or a log line.

Use the literal `127.0.0.1`, not the hostname `localhost` — per RFC 8252 §7.3, `localhost` can be redirected by a hosts file or DNS and is not guaranteed to stay on the loopback adapter.

> ⚠️ **Okta matches redirect URIs exactly, including the port.** RFC 8252 §7.3 *recommends* that authorization servers allow any port for loopback redirects, but do not rely on it. **Register a small fixed pool of ports** on the app integration — `http://127.0.0.1:8765/callback`, `:8766`, `:8767` — and have the client probe them in order, failing over when one is already bound. Three ports removes the "port already in use" support ticket without creating an unmanageable allowlist. Implementation in §8.5.

### 4.4 `private_key_jwt` for the API service identities — **chosen**

Where `ApiA` or `ApiB` authenticates to Okta as itself (§7), it does so with a **signed JWT assertion** backed by an X.509 certificate, not a shared client secret.

- A shared secret must be transported to every server, and lives in a config file or environment variable where it can be read, logged, or committed.
- The private key of a certificate can be generated **on the server**, marked non-exportable, stored in the Windows certificate store, and never transported at all.
- Rotation is an overlap of two registered public keys rather than a synchronised secret swap with downtime.
- Okta requires `private_key_jwt` for service apps requesting Okta-scoped tokens, so you will need this capability anyway.

### 4.5 Rejected: Resource Owner Password Credentials (`password` grant)

Superficially attractive for a desktop app — put a Telerik login form in the shell, POST username and password to Okta, done. **Do not do this.**

- Removed from OAuth 2.1 and formally deprecated by the [OAuth 2.0 Security BCP §2.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics).
- It puts `AppA` back into the credential-handling business — the precise thing SSO exists to eliminate.
- MFA, passkeys, device trust, and federation to an upstream IdP either break outright or are silently bypassed.
- It destroys cross-app SSO: there is no browser session, so `AppB` must prompt again. You would be building the *opposite* of the requirement.
- It makes every application an equally attractive credential-phishing target, and normalises the behaviour you are trying to train users out of.

### 4.6 Rejected: Implicit flow and hybrid `response_type=id_token token`

Tokens delivered in URL fragments leak into browser history, `Referer` headers, proxy logs, and crash dumps, and cannot be bound to the client with PKCE. Prohibited by the OAuth 2.0 Security BCP. Use `response_type=code` exclusively.

### 4.7 Rejected: a shared token cache between `AppA` and `AppB`

Tempting as an SSO shortcut, but a compromise of the less-hardened application yields the other's refresh tokens, and per-application revocation becomes impossible. Use one of the three legitimate mechanisms in §10.

### 4.8 Decision summary

| Decision | Choice | Primary driver |
|---|---|---|
| Grant type | Authorization Code + PKCE | RFC 8252; public client holds no secret |
| User agent | System browser | SSO cookie, anti-phishing, passkeys |
| Redirect | Loopback, fixed port pool | No registry writes, no scheme hijacking |
| Client auth (WPF) | `none` + PKCE | Public client, cannot keep a secret |
| Client auth (APIs) | `private_key_jwt`, X.509 | Key never leaves the server |
| Authorization Server | Custom AS | Required for your own audiences and scopes |
| Token format | JWT, validated offline | No IdP round trip on the request path |
| Access token lifetime | 10–15 min | JWTs cannot be revoked; short life *is* the control |
| Refresh token | Rotating, via `offline_access` | Reuse detection catches theft |
| Cross-app SSO | Okta browser session | Requires no additional Okta features |
| Service-to-service | **See §7 — decision pending** | Four patterns documented, matrix in §7.6 |
---

# Part II — Configure

## 5. Okta tenant design

### 5.1 Org Authorization Server vs Custom Authorization Server

Okta has two kinds of authorization server, and choosing wrongly makes a correct implementation impossible. This is the single most consequential Okta-specific decision in the document.

| | **Org Authorization Server** | **Custom Authorization Server** |
|---|---|---|
| Issuer | `https://{yourOktaDomain}` | `https://{yourOktaDomain}/oauth2/{authServerId}` |
| Purpose | Authenticating to **Okta's own APIs** | Protecting **your** APIs |
| Custom scopes | ❌ Not possible | ✅ Yes |
| Custom `aud` | ❌ Fixed to the Okta org URL | ✅ You define it (`api://apia`) |
| Custom claims | ❌ Limited | ✅ Full expression language |
| Per-app token lifetimes | ❌ | ✅ Via access policies |
| Token exchange / OBO | ❌ | ✅ |
| Requires | Nothing | **API Access Management** |

> ⚠️ **You must use a Custom Authorization Server.** The Org AS cannot issue a token whose `aud` is `api://apia`, so `ApiA` and `ApiB` could not distinguish tokens meant for each other — a token stolen from one would be valid at the other, and Rule 1 becomes unenforceable. It also cannot define `apia.read`, so all authorization would collapse to "is authenticated".
>
> API Access Management is **included** in Okta Integrator Free Plan / developer orgs. In a paid production org it is a **licensed add-on** — confirm your org has it before the demo, or you will hit a wall late. Verify in **Admin Console → Security → API**: if you can see an **Authorization Servers** tab with an **Add Authorization Server** button, you have it.

Every Okta org with API Access Management ships with a pre-created Custom AS named `default`, reachable at `https://{yourOktaDomain}/oauth2/default`. It is fine for the demo. For production, create named servers — `default` is shared with every other project in the tenant and its policies will drift.

References: [Authorization servers](https://developer.okta.com/docs/concepts/auth-servers/) · [API Access Management](https://developer.okta.com/docs/concepts/api-access-management/)

### 5.2 Topology: two options

You selected *one Custom AS with two audiences*. Since that choice was made, two facts came to light that you should weigh before committing — both documented below, with a recommendation.

#### Variant A — One Custom AS, two audiences *(your selection)*

```
Custom AS  "corp-apis"   issuer https://{domain}/oauth2/{corpAsId}
├── audiences: api://apia  (default), api://apib
├── scopes:    apia.read, apia.write, apib.read, apib.write
├── claims:    groups, uid
└── policies:  one per client app
```

The client selects which audience it wants using the **`resource` parameter** ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)) on the `/authorize` or `/token` request. Okta binds the resulting `aud` to the requested resource. Without a `resource` parameter, tokens get the server's *default* audience.

**Advantages:** one issuer to configure, one JWKS endpoint, one set of policies, and token exchange between the two APIs needs no cross-server trust configuration.

> ⚠️ **Variant A depends on a self-service Early Access feature.** *Multiple audiences for custom authorization servers* is a self-service EA feature in Okta, enabled under **Admin Console → Settings → Features**. EA features are supported but may change, and are not always available in every org type or region. **Verify it is available and enabled in your target production tenant before designing around it.** A maximum of 100 audience URLs is supported.

#### Variant B — One Custom AS per API — **recommended**

```
Custom AS  "apia-as"   issuer https://{domain}/oauth2/{apiaAsId}
├── audience: api://apia
└── scopes:   apia.read, apia.write

Custom AS  "apib-as"   issuer https://{domain}/oauth2/{apibAsId}
├── audience: api://apib
├── scopes:   apib.read, apib.write
└── trusted servers: apia-as        ← required for OBO token exchange
```

**Why this is the safer default:**

- **Generally available.** No dependency on an EA feature, in any org type.
- **It is the topology Okta's own On-Behalf-Of Token Exchange guide uses** — two custom authorization servers, made mutually trusted. If §7 Pattern 1 wins, you are already on the documented path.
- **Blast radius.** A misconfigured policy, a bad claim expression, or a compromised signing key affects one API, not both.
- **Independent lifetimes and policies.** `ApiB` can demand 5-minute tokens and MFA while `ApiA` runs at 15 minutes, with no coupling.
- **Independent evolution.** Teams can change their own server without a cross-team review.

The cost is real but small: two issuers in configuration, two JWKS endpoints cached, and — if you adopt OBO — an explicit **trusted server** relationship to declare.

> **Recommendation:** build the demo on **Variant B**. The extra configuration is perhaps twenty minutes; it removes an EA dependency from your production critical path and lines up with Okta's documented OBO topology. The rest of this document is written so that both variants work — where they differ, the difference is called out inline, and only the issuer/audience values in [Appendix B](#appendix-b--configuration-reference-sheet) change.

### 5.3 Application inventory

Six Okta objects. Get this table right and the rest is mechanical.

| # | Okta object | App type | Client auth | Grants | Represents |
|---|---|---|---|---|---|
| 1 | `AppA — WPF Client` | Native Application | `none` (PKCE) | `authorization_code`, `refresh_token` | The `AppA` desktop app |
| 2 | `AppB — WPF Client` | Native Application | `none` (PKCE) | `authorization_code`, `refresh_token` | The `AppB` desktop app |
| 3 | `ApiA — Service` | API Services | `private_key_jwt` | `client_credentials`, *(+ `token_exchange` if §7 P1)* | `ApiA`'s **own** identity |
| 4 | `ApiB — Service` | API Services | `private_key_jwt` | `client_credentials`, *(+ `token_exchange` if §7 P1)* | `ApiB`'s **own** identity |
| 5 | Custom AS + audience `api://apia` | — | — | — | `ApiA` **as a resource** |
| 6 | Custom AS + audience `api://apib` | — | — | — | `ApiB` **as a resource** |

> ⚠️ **`ApiA` appears twice, and this trips people up.** Rows 3 and 5 are different things.
> - Row **5** is `ApiA` as a **resource server** — the *destination* of a token. It is not an app integration at all; it is just an audience string on an authorization server. `ApiA` needs no Okta credentials to validate tokens, only Okta's public keys.
> - Row **3** is `ApiA` as a **client** — the *origin* of an outbound call to `ApiB`. This one has a `client_id` and a signing certificate.
>
> If `ApiA` never calls `ApiB`, row 3 does not exist. Because your architecture has mutual calls, both APIs need both roles.

### 5.4 Scope design

Scopes answer *"what class of operation is this token permitted to perform?"* They are the coarse, IdP-visible layer of authorization. Fine-grained decisions ("may Alice edit **this** order?") belong in your application, not in the token — see §5.6.

Recommended scheme, `{api}.{action}`:

| Scope | Granted to | Meaning |
|---|---|---|
| `apia.read` | AppA, AppB, ApiB | Read `ApiA` resources |
| `apia.write` | AppA | Mutate `ApiA` resources |
| `apib.read` | AppB, AppA, ApiA | Read `ApiB` resources |
| `apib.write` | AppB | Mutate `ApiB` resources |
| `openid`, `profile`, `email` | AppA, AppB | Standard OIDC — identity for the UI |
| `offline_access` | AppA, AppB | Issue a refresh token |

Design rules that hold up in production:

- **Scopes describe the API's capabilities, not the user's job title.** `apia.write`, not `apia.manager`. Job titles change; endpoints do not. Roles come from `groups` (§5.5).
- **Never define a `*.admin` or `full_access` scope.** It becomes the default request in every app within a year, and you lose the ability to reason about blast radius.
- **Request the minimum per app.** `AppA` should not request `apib.write` merely because it might one day need it — every unnecessary scope widens the damage from a stolen token.
- **Do not mark scopes as default/implicitly granted.** Requiring explicit consent-free grants via policy keeps the grant surface auditable.

> ⚠️ **Request one audience's scopes at a time.** A single access token has exactly one `aud`. When `AppA` needs to call both APIs, it makes **two token requests** and holds **two access tokens** — one per audience — from the *same* browser session, silently. That is correct and normal, not a design smell. §8.9 implements it.

### 5.5 Claims: groups and roles

Identity lives in Okta; permissions live in your application. The bridge is a **groups claim**.

Configure on each Custom AS: **Security → API → {your AS} → Claims → Add Claim**

| Field | Value |
|---|---|
| Name | `groups` |
| Include in token type | **Access Token** |
| Value type | **Groups** |
| Filter | **Starts with** `App-` |
| Include in | The scopes/policies you choose |

The `Starts with App-` filter matters. Without it you emit *every* group the user belongs to — in a real tenant that can be hundreds of entries, which bloats the token past proxy and IIS header limits (§14.3) and leaks the org chart to every resource server. Name application-relevant groups with a prefix (`App-Finance`, `App-Warehouse`, `App-OrdersAdmin`) and filter to it.

> ⚠️ **Do not put fine-grained permissions in the token.** It is tempting to emit a `permissions` claim with every action the user may perform. Three reasons not to:
> 1. **Staleness.** A token minted 14 minutes ago carries permissions as they were 14 minutes ago. Revoking access requires waiting out the token lifetime, on *every* permission change rather than only on sign-out.
> 2. **Size.** JWTs travel in an HTTP header. IIS defaults to a 16 KB request-header limit; a permissions matrix will find it (§14.3).
> 3. **Coupling.** Every new permission becomes an Okta change request, gated by an identity team, for a change owned by an application team.
>
> Emit **groups**; resolve *group → permissions* inside each API, where it can be cached, versioned, and changed at application speed.

### 5.6 Access policies, rules, and token lifetimes

An access policy on the Custom AS decides, per client, which scopes are granted and how long tokens live.

**Security → API → {your AS} → Access Policies → Add Policy**, then add rules to it.

Recommended baseline:

| Setting | Value | Rationale |
|---|---|---|
| Access token lifetime | **15 minutes** (10 for `ApiB` if it holds sensitive data) | A JWT cannot be revoked mid-life. Short lifetime **is** your revocation window. |
| Refresh token lifetime | **90 days**, expires if unused for **7 days** | Balances "don't make me sign in daily" against dormant-token risk. |
| Refresh token rotation | **Rotate** | Enables reuse detection. See below. |
| Rotation grace period | **30 seconds** | Survives a network retry that races the rotation. Okta allows 0–60; the default is 30. |
| Assigned to | Specific client(s) | One policy per app, never "All clients" |

**Refresh token rotation** means each use of a refresh token invalidates it and returns a new one. Its value is **theft detection**: if an old refresh token is ever presented again after rotation (outside the grace period), that is proof either the client or the attacker has a stale copy — Okta invalidates the entire token family. Without rotation, a stolen refresh token grants silent access for its full 90-day life with no signal at all.

The **grace period** exists because rotation has a genuine race: the client sends a refresh request, Okta rotates and responds, and the response is lost to a dropped connection. The client retries with the old token. Without a grace window that legitimate retry looks like theft and signs the user out. 30 seconds is the right default; do not set it to 0.

Reference: [Refresh access tokens and rotate refresh tokens](https://developer.okta.com/docs/guides/refresh-tokens/main/)

### 5.7 Trusted servers *(Variant B + §7 Pattern 1 only)*

If you adopt Variant B **and** On-Behalf-Of token exchange, `ApiB`'s authorization server must be told to trust tokens issued by `ApiA`'s.

**Security → API → `apib-as` → Trusted Servers → Add Trusted Server → `apia-as`**

Semantics: when a token-exchange request arrives at `apib-as` carrying a `subject_token` that was issued by `apia-as`, the trust relationship permits `apib-as` to accept that token as evidence of the user's identity and mint a new one for `api://apib`.

> ⚠️ **Trust is directional, and that is the point.** Adding `apia-as` as a trusted server on `apib-as` lets `ApiA` act on a user's behalf at `ApiB`. It does **not** let `ApiB` act at `ApiA`. Because your architecture has calls in both directions, you must configure the relationship **both ways** — but do so as two deliberate decisions, not one. If only one direction is actually needed, configure only that one.
>
> Okta documents that trusted servers support **only** on-behalf-of token exchanges — the relationship does not confer any other capability.

Reference: [Add trusted servers](https://help.okta.com/oie/en-us/content/topics/security/api-add-trusted-servers.htm)

---

## 6. Okta configuration walkthrough

Work through this in order. Record every generated ID in [Appendix B](#appendix-b--configuration-reference-sheet) as you go.

### 6.1 Prerequisites

- An Okta org with **API Access Management** (§5.1).
- Admin access with the **Super Administrator** or **API Access Management Administrator** role.
- For Variant A only: *Multiple audiences for custom authorization servers* enabled under **Settings → Features**.
- For §7 Pattern 1 only: **Token Exchange** available on your org.

### 6.2 Create the authorization servers

**Security → API → Authorization Servers → Add Authorization Server**

*Variant B (recommended):*

| Field | `apia-as` | `apib-as` |
|---|---|---|
| Name | `ApiA Authorization Server` | `ApiB Authorization Server` |
| Audience | `api://apia` | `api://apib` |
| Description | Issues tokens for ApiA | Issues tokens for ApiB |

*Variant A:* one server named `Corp APIs`, audience `api://apia`, then **Settings → Edit → Add another audience →** `api://apib`. The first entry becomes the default `aud` when no `resource` parameter is supplied.

Record the generated **Authorization Server ID** (`aus…`) for each. Confirm each server's metadata resolves:

```
https://{yourOktaDomain}/oauth2/{authServerId}/.well-known/openid-configuration
```

That document is the contract between Okta and your APIs. Every value your code needs — `issuer`, `jwks_uri`, `token_endpoint`, `authorization_endpoint`, `end_session_endpoint`, and the supported grant types — comes from it. **If it does not resolve, stop and fix that before writing any code.**

### 6.3 Create the scopes

On each AS: **Scopes → Add Scope**. For every scope in §5.4:

| Field | Value |
|---|---|
| Name | `apia.read` |
| Display phrase | `Read ApiA data` |
| Description | Shown on any consent prompt |
| User consent | **Implicit** (first-party apps) |
| Default scope | ❌ **Unchecked** |
| Metadata | Include in public metadata — optional |

*User consent: Implicit* is correct for first-party corporate applications — you do not want employees clicking a consent screen for your own line-of-business app. It would be wrong for a third-party integration.

### 6.4 Create the groups claim

On each AS: **Claims → Add Claim**. Use the settings in §5.5. Then **Token Preview** (below) to confirm it appears.

### 6.5 Create the app integrations

**Applications → Applications → Create App Integration**

**For `AppA` and `AppB`** — *OIDC – OpenID Connect* → *Native Application*:

| Field | Value |
|---|---|
| App name | `AppA — WPF Client` |
| Grant types | ✅ Authorization Code · ✅ Refresh Token · ❌ everything else |
| Sign-in redirect URIs | `http://127.0.0.1:8765/callback`<br>`http://127.0.0.1:8766/callback`<br>`http://127.0.0.1:8767/callback` |
| Sign-out redirect URIs | `http://127.0.0.1:8765/signout-callback` *(+ 8766, 8767)* |
| Client authentication | **None** (PKCE is enforced automatically) |
| Assignments | Only the groups that should have the app |

**For `ApiA` and `ApiB` service identities** — *API Services*:

| Field | Value |
|---|---|
| App name | `ApiA — Service Identity` |
| Grant types | ✅ Client Credentials *(+ ✅ Token Exchange for §7 P1)* |
| Client authentication | **Public key / Private key** → `private_key_jwt` |
| Public keys | Paste the **public** JWK generated in §6.6 |

> ⚠️ **Assignments are a separate gate from policy (§3.5).** A brand-new app integration has no users assigned. The most common "it worked in the walkthrough and fails for real users" cause is a missing group assignment producing `access_denied` with no other explanation.

### 6.6 Generate the service signing keys

Do this **on the server that will use the key**, so the private key never travels.

```powershell
# Run on the IIS host, as Administrator.
# Self-signed is appropriate here: Okta trusts the registered PUBLIC key
# directly, so there is no chain to validate and no CA to involve.

$cert = New-SelfSignedCertificate `
  -Subject "CN=ApiA-Okta-ClientAuth" `
  -CertStoreLocation "Cert:\LocalMachine\My" `
  -KeyExportPolicy NonExportable `
  -KeySpec Signature `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -HashAlgorithm SHA256 `
  -NotAfter (Get-Date).AddYears(2)

$cert.Thumbprint   # record this in Appendix B

# Export the PUBLIC certificate only, to register with Okta.
Export-Certificate -Cert $cert -FilePath "$env:TEMP\ApiA-Okta-Public.cer"
```

`-KeyExportPolicy NonExportable` is the point of the exercise: the private key cannot be copied off the machine even by an administrator, so it cannot leak through a backup, a config file, or a support bundle.

Convert the public certificate to a JWK for Okta's *Public keys* field:

```powershell
$c   = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$env:TEMP\ApiA-Okta-Public.cer")
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c)
$p   = $rsa.ExportParameters($false)

$b64u = { param($b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }

@{
  kty = "RSA"
  kid = $c.Thumbprint
  use = "sig"
  alg = "RS256"
  n   = (& $b64u $p.Modulus)
  e   = (& $b64u $p.Exponent)
} | ConvertTo-Json
```

> ⚠️ **Register two keys before you need to rotate.** Okta accepts multiple public keys per app. Add the replacement key while the old one is still live, deploy the new certificate, verify traffic has moved (System Log shows the `kid` in use), *then* remove the old key. Rotating in one step means downtime.

### 6.7 Create the access policies

On each AS: **Access Policies → Add Policy**, one per client, then **Add Rule**:

| Rule field | `AppA` policy | `ApiA` service policy |
|---|---|---|
| Grant type is | Authorization Code | Client Credentials / Token Exchange |
| User is | Any user assigned the app | *(N/A — no user)* |
| Scopes requested | The specific scopes, listed | The specific scopes, listed |
| Access token lifetime | 15 minutes | 15 minutes |
| Refresh token lifetime | 90 days / 7-day idle | *(N/A)* |

Rules are evaluated **top to bottom, first match wins**. Order matters. Keep any catch-all deny rule last, and prefer explicit per-client rules over broad ones.

### 6.8 Verify with Token Preview

Every Custom AS has a **Token Preview** tab. Use it before writing a line of code.

Select the client, the grant type, a real user, and the scopes; Okta shows the exact token it would mint. Confirm:

- `aud` is `api://apia` — **not** the Okta org URL, and not the `client_id`
- `iss` is `https://{yourOktaDomain}/oauth2/{authServerId}`
- `scp` contains exactly the scopes you expect and nothing more
- `groups` is present, filtered, and not hundreds of entries long
- `exp - iat` matches your configured lifetime

> ⚠️ **If Token Preview returns an error, no client code will ever work.** It is the same policy engine. Almost every "my token is rejected" problem is visible here in thirty seconds, and diagnosable from the System Log (§14.1). Do not proceed past a failing Token Preview.

### 6.9 Infrastructure as code

Click-ops does not survive contact with three environments. Once the design is settled, move it to Terraform with the [Okta provider](https://registry.terraform.io/providers/okta/okta/latest/docs). Sketch:

```hcl
resource "okta_auth_server" "apia" {
  name        = "ApiA Authorization Server"
  description = "Issues access tokens for ApiA"
  audiences   = ["api://apia"]
}

resource "okta_auth_server_scope" "apia_read" {
  auth_server_id   = okta_auth_server.apia.id
  name             = "apia.read"
  display_name     = "Read ApiA data"
  description      = "Read access to ApiA resources"
  consent          = "IMPLICIT"
  metadata_publish = "ALL_CLIENTS"
}

resource "okta_auth_server_claim" "apia_groups" {
  auth_server_id = okta_auth_server.apia.id
  name           = "groups"
  value          = "App-.*"
  value_type     = "GROUPS"
  group_filter_type = "STARTS_WITH"
  claim_type     = "RESOURCE"          # access token
}

resource "okta_app_oauth" "appa" {
  label                      = "AppA — WPF Client"
  type                       = "native"
  grant_types                = ["authorization_code", "refresh_token"]
  response_types             = ["code"]
  token_endpoint_auth_method = "none"
  redirect_uris = [
    "http://127.0.0.1:8765/callback",
    "http://127.0.0.1:8766/callback",
    "http://127.0.0.1:8767/callback",
  ]
  post_logout_redirect_uris = ["http://127.0.0.1:8765/signout-callback"]
}
```

Verify resource and attribute names against the provider version you pin — the Okta provider has changed schemas across major versions. Trusted-server relationships (§5.7) and some EA features may not have provider coverage; configure those via the [Authorization Servers Management API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/authorizationserver) and record them in the runbook so they are not lost on a tenant rebuild.
---

# Part III — Build

## 7. ApiA ↔ ApiB: the four delegation patterns

This is the most consequential section in the document, and the decision is still open by design.

Your architecture has `ApiA` and `ApiB` calling **each other**. Every such call must answer one question before any code is written:

> ### Under whose authority is this call made?

There are only two honest answers, and they lead to different flows:

- **"Under the service's own authority."** `ApiA` is doing something it is entitled to do regardless of any user — a nightly reconciliation, a cache warm, a health probe. → **Pattern 2**.
- **"Under the user's authority."** Alice clicked a button in `AppA`; `ApiA` needs data from `ApiB` *that Alice is entitled to see*. → **Patterns 1, 3, or 4**.

Answering "both, sort of" means you have not decomposed the call yet. Split it.

> ⚠️ **Correction to a widely repeated claim.** Okta was for years documented as having no On-Behalf-Of flow, and much third-party guidance still says so. **That is out of date.** Okta now documents [OAuth 2.0 On-Behalf-Of Token Exchange](https://developer.okta.com/docs/guides/set-up-token-exchange/main/) — a profile of [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — for exactly this scenario, working within a single custom authorization server or between two under the same tenant via a trusted-server relationship. This materially changes the recommendation: Pattern 1 is available to you, and it is the strongest option.

### 7.1 Pattern 1 — On-Behalf-Of Token Exchange (RFC 8693) ⭐ recommended

`ApiA` presents the user's access token to Okta and receives a **new** token, audience `api://apib`, that still carries the user's identity.

```
AppA ──── Bearer (aud=api://apia, sub=alice) ────► ApiA
                                                    │
                                    ┌───────────────┘
                                    ▼
                         POST /oauth2/{apibAsId}/v1/token
                         grant_type   = ...:token-exchange
                         subject_token= <alice's token for ApiA>
                         audience     = api://apib
                         scope        = apib.read
                         client_assertion = <ApiA's signed JWT>
                                    │
                                    ▼
                         ◄── access_token
                             aud = api://apib
                             sub = alice          ← user preserved
                             cid = ApiA           ← actor recorded
                                    │
ApiA ──── Bearer (aud=api://apib, sub=alice) ────► ApiB
                                                    │
                                          ApiB enforces ITS OWN
                                          authorization for alice
```

**Why this is the correct answer.** It is the only pattern that satisfies both audience rules while preserving user identity end to end:

- The token `ApiB` receives has `aud=api://apib`. Rule 1 holds — `ApiB` accepts a token genuinely addressed to it.
- `ApiA` never forwards a credential outside its audience. Rule 2 holds.
- `ApiB` sees `sub=alice` and enforces **its own** authorization. It does not have to trust `ApiA`'s judgement about what Alice may see.
- The exchanged token cannot be replayed against `ApiA` — wrong audience.
- **Okta re-evaluates policy at exchange time.** If Alice is deprovisioned, or the `ApiA→ApiB` scope grant is revoked, the exchange fails immediately rather than succeeding because `ApiA` decided it should.
- The audit trail is complete on both sides: `ApiB`'s System Log entry records both the user and the calling client.

**Prerequisites:**
- Both authorization servers are Custom (§5.1).
- The `ApiA — Service` app integration has the **Token Exchange** grant enabled and `private_key_jwt` client auth.
- Variant B only: `apia-as` added as a **trusted server** on `apib-as` (§5.7).
- Scopes `apib.read` etc. granted to the `ApiA` service app by policy.

**The request:**

```http
POST /oauth2/{apibAsId}/v1/token HTTP/1.1
Host: {yourOktaDomain}
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&subject_token=eyJraWQiOi...            ← Alice's token for ApiA
&audience=api%3A%2F%2Fapib
&scope=apib.read
&client_id={apiaServiceClientId}
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOi...         ← ApiA's private_key_jwt
```

> ⚠️ **Okta limitation:** a service app performing token exchange **cannot** request `offline_access` or any OIDC scope (`openid`, `profile`, `email`). Exchanged tokens are short-lived access tokens only — no refresh token, no ID token. This is correct behaviour, not a gap: a service acting on a user's behalf must re-derive its authority from a live user token each time, never hold a standing long-lived one.

**Implementation.** Two pieces: a client-assertion factory (reused by Patterns 1 and 2) and the exchange client.

```csharp
// ── Signs the private_key_jwt used to authenticate ApiA to Okta ──────────
public interface IClientAssertionFactory { string Create(); }

public sealed class X509ClientAssertionFactory : IClientAssertionFactory
{
    private readonly OktaServiceOptions _o;
    private readonly ILogger<X509ClientAssertionFactory> _log;

    public X509ClientAssertionFactory(IOptions<OktaServiceOptions> o,
                                      ILogger<X509ClientAssertionFactory> log)
        => (_o, _log) = (o.Value, log);

    public string Create()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        var cert = store.Certificates
            .Find(X509FindType.FindByThumbprint, _o.SigningCertificateThumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault()
            ?? throw new InvalidOperationException(
                   $"Client-auth certificate {_o.SigningCertificateThumbprint} not found in " +
                   "LocalMachine\\My. Check the thumbprint and the app-pool identity's " +
                   "read access to the private key (see §13.3).");

        if (cert.NotAfter < DateTime.UtcNow.AddDays(14))
            _log.LogWarning("Okta client-auth certificate expires {NotAfter:u} — rotate now (§6.6)",
                            cert.NotAfter);

        var now = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer   = _o.ClientId,
            // Okta requires the assertion audience to be the exact token endpoint URL.
            Audience = $"{_o.Issuer}/v1/token",
            Subject  = new ClaimsIdentity(new[]
            {
                new Claim("sub", _o.ClientId),
                new Claim("jti", Guid.NewGuid().ToString("N")),  // replay protection
            }),
            IssuedAt  = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires   = now.AddMinutes(5).UtcDateTime,   // keep short; Okta caps this
            SigningCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}
```

```csharp
// ── Exchanges a user's token for a downstream one ────────────────────────
public sealed class OktaTokenExchangeService
{
    private const string GrantTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";
    private const string AssertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private readonly HttpClient _http;
    private readonly IClientAssertionFactory _assertions;
    private readonly IDelegatedTokenCache _cache;
    private readonly OktaServiceOptions _o;
    private readonly ILogger<OktaTokenExchangeService> _log;

    public async Task<string> ExchangeAsync(
        string subjectToken, string audience, string scope, CancellationToken ct)
    {
        // Cache key must be scoped to the SUBJECT, or one user's delegated token
        // is served to another. Hash the token: never use it as a raw key, and
        // never log it.
        var key = DelegatedTokenCacheKey.For(subjectToken, audience, scope);
        if (_cache.TryGet(key, out var cached))
            return cached;

        using var req = new HttpRequestMessage(HttpMethod.Post, $"{_o.Issuer}/v1/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]            = GrantTokenExchange,
                ["subject_token_type"]    = TokenTypeAccessToken,
                ["subject_token"]         = subjectToken,
                ["audience"]              = audience,
                ["scope"]                 = scope,
                ["client_id"]             = _o.ClientId,
                ["client_assertion_type"] = AssertionType,
                ["client_assertion"]      = _assertions.Create(),
            })
        };

        using var res = await _http.SendAsync(req, ct);
        var body = await res.Content.ReadAsStringAsync(ct);

        if (!res.IsSuccessStatusCode)
        {
            // The body carries RFC 6749 error/error_description. It does NOT
            // contain the tokens, so it is safe to log — and it is the single
            // most useful diagnostic you will have. See §14.2.
            _log.LogError("Token exchange to {Audience} failed: {Status} {Body}",
                          audience, (int)res.StatusCode, body);
            throw new TokenExchangeException(audience, res.StatusCode, body);
        }

        var token = JsonSerializer.Deserialize<OktaTokenResponse>(body)!;

        // Expire the cache entry before the token does, and never past the
        // subject token's own expiry — delegated authority must not outlive
        // the authority it was derived from.
        var subjectExp = JwtExpiry.Of(subjectToken);
        var ttl = TimeSpan.FromSeconds(token.ExpiresIn - 30);
        if (subjectExp is { } exp)
            ttl = Min(ttl, exp - DateTimeOffset.UtcNow - TimeSpan.FromSeconds(30));

        if (ttl > TimeSpan.Zero)
            _cache.Set(key, token.AccessToken, ttl);

        return token.AccessToken;
    }
}
```

> ⚠️ **Cache exchanged tokens, but key them by subject.** Without a cache you make an Okta round trip on every downstream call — latency, rate-limit pressure, and an availability dependency on Okta for every request. With a cache keyed only by `(audience, scope)` you will serve Alice's delegated token to Bob. Hash the subject token into the key, cap the entry's lifetime at the subject's own expiry, and never write the key material to a log.

### 7.2 Pattern 2 — Client credentials (service acting as itself)

For calls with **no user** — scheduled jobs, cache priming, health checks, bulk reconciliation.

```
ApiA ──► Okta:  grant_type=client_credentials
                scope=apib.read
                client_assertion=<ApiA's signed JWT>
     ◄── access_token   aud=api://apib, cid=ApiA, NO sub
ApiA ──► ApiB:  Bearer <that token>
```

```csharp
public sealed class OktaClientCredentialsService
{
    public async Task<string> GetTokenAsync(string scope, CancellationToken ct)
    {
        if (_cache.TryGet(scope, out var cached)) return cached;

        using var res = await _http.PostAsync($"{_o.Issuer}/v1/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]            = "client_credentials",
                ["scope"]                 = scope,
                ["client_id"]             = _o.ClientId,
                ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ["client_assertion"]      = _assertions.Create(),
            }), ct);

        var body = await res.Content.ReadAsStringAsync(ct);
        if (!res.IsSuccessStatusCode)
            throw new OktaTokenException(res.StatusCode, body);

        var token = JsonSerializer.Deserialize<OktaTokenResponse>(body)!;
        _cache.Set(scope, token.AccessToken, TimeSpan.FromSeconds(token.ExpiresIn - 60));
        return token.AccessToken;
    }
}
```

A service-credentials token is safe to cache by scope alone — there is no user to leak across.

> ⚠️ **A client-credentials token is broader authority than any single user's.** It typically carries the union of what every user could do, with no per-user constraint. Two consequences:
> 1. **Never use it to serve a user-initiated request.** If a request arrived because Alice clicked something, using a service token means `ApiB` authorises the *service*, and Alice's own permissions are never checked. That is a privilege-escalation path disguised as a convenience.
> 2. **Give it the narrowest scopes that work,** and monitor its use separately in the System Log. `cid` with no `sub` is trivially alertable.

### 7.3 Pattern 3 — Client relays a second token

`AppA` silently acquires a **second** access token with `aud=api://apib` and sends it to `ApiA` alongside the first, in a distinct header. `ApiA` forwards it to `ApiB`.

```
AppA ──► Okta: token #1  aud=api://apia
AppA ──► Okta: token #2  aud=api://apib     ← same session, silent
AppA ──► ApiA:  Authorization:  Bearer <#1>
                X-Downstream-Authorization: Bearer <#2>
ApiA ──► ApiB:  Authorization:  Bearer <#2>
```

Both audience rules are technically satisfied, and `ApiB` enforces its own authorization for the real user. It requires no service identity and no token-exchange feature, so it works on any Okta org.

**But it is worse than Pattern 1 on four counts:**

- **Wider exposure.** The desktop — the least trusted machine in the estate — now holds credentials for an API it never calls directly. Compromising the workstation yields access to `ApiB` too.
- **The client must know the server's call graph.** If `ApiA` later needs `ApiC`, you must ship a new desktop client. Backend refactoring becomes a client release. This coupling is the reason the pattern decays.
- **Non-standard transport.** `X-Downstream-Authorization` is a bespoke convention. Every proxy, gateway, and library has to be taught about it, and it will be dropped by something eventually.
- **No actor record.** `ApiB` cannot tell whether Alice called it directly or `ApiA` did on her behalf. The audit trail loses a hop.

Reasonable as a **stopgap** if token exchange is unavailable in your org. Not a destination.

### 7.4 Pattern 4 — Shared audience passthrough

Both APIs share one audience (`api://corp`), so a single user token is valid at both, and `ApiA` forwards it unchanged.

**Simplest to build, and materially the weakest.** The audience is what makes a token addressable; collapsing it collapses the security boundary:

- A token stolen from `ApiA` — via a log file, an exception dump, an SSRF, a crash report — is immediately valid at `ApiB`. There is no containment.
- Scope becomes the only boundary, and scope is coarser and more easily over-granted.
- The APIs can never be separated later without a coordinated client change.
- `ApiB` cannot distinguish a direct user call from a relayed one, so it cannot apply different policy to the two.

> ⚠️ **Legitimate use is narrow.** Pattern 4 is defensible only when `ApiA` and `ApiB` are genuinely *one* security domain — two deployments of a single logical service, in one trust boundary, one team, one release train, sharing a datastore. Two APIs that "are both ours" is **not** the same thing. If you are choosing this because token exchange looked like work, choose Pattern 3 instead.

### 7.5 The anti-pattern: forwarding the `ApiA` token to `ApiB`

Not a fifth option — the defect all four patterns exist to avoid. `ApiA` takes the token it received (`aud=api://apia`) and forwards it to `ApiB`, which accepts it.

To accept it, `ApiB` must disable audience validation, or add `api://apia` to its valid audiences. Either way:

1. **`ApiB` now holds a live credential for `ApiA`** and can replay it — as can anything that reads `ApiB`'s logs, memory, or crash dumps.
2. **`ApiB` cannot verify the call was authorised.** The token proves Alice authenticated and may use `ApiA`. It says nothing about whether `ApiA` may act at `ApiB`. `ApiB` becomes a **confused deputy**: it holds authority, and acts on a request whose legitimacy it cannot establish.
3. **The blast radius of one compromised service becomes every service** it can reach.

The tell in a code review is an API with `ValidateAudience = false`, a `ValidAudiences` list containing another service's identifier, or an outbound handler that copies `Request.Headers.Authorization` verbatim. §9.2 and §15.2 make each of those a test failure.

### 7.6 Decision matrix

| | **P1 · OBO exchange** | **P2 · Client creds** | **P3 · Client relay** | **P4 · Shared audience** |
|---|---|---|---|---|
| User identity reaches `ApiB` | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| `ApiB` enforces its own user authz | ✅ Yes | ❌ N/A | ✅ Yes | ✅ Yes |
| Both audience rules satisfied | ✅ | ✅ | ✅ | ⚠️ Vacuously |
| Audience isolation between APIs | ✅ | ✅ | ✅ | ❌ **None** |
| Actor (`ApiA`) recorded downstream | ✅ | ✅ (`cid`) | ❌ | ❌ |
| Policy re-evaluated per delegation | ✅ | ✅ | ❌ | ❌ |
| Token exposure on the desktop | Minimal | None | **Elevated** | Minimal |
| Client coupled to server call graph | ❌ No | ❌ No | ⚠️ **Yes** | ❌ No |
| Okta feature required | Token Exchange | — | — | — |
| Extra Okta round trip per call | Yes (cached) | Yes (cached) | No | No |
| Service identity + cert needed | Yes | Yes | No | No |
| **Verdict** | **Recommended** | For user-less work | Stopgap | Rarely |

**Recommendation:** **Pattern 1 for user-initiated calls, Pattern 2 for background work.** They are complementary, not alternatives — a mature system uses both, chosen per call site, and never mixes them up.

If your org cannot enable Token Exchange, use **Pattern 3** and record it as accepted technical debt with a trigger condition for revisiting.

**To validate the choice before committing**, run this spike (30 minutes):
1. Enable Token Exchange on the `ApiA — Service` app.
2. Configure the trusted-server relationship (Variant B).
3. Obtain a real user token for `api://apia` via Token Preview or a `curl` PKCE flow.
4. `curl` the exchange request from §7.1 and decode the result.
5. Confirm `aud=api://apib` and `sub` is the original user.

If step 5 succeeds, take Pattern 1. That single check settles the decision on evidence rather than on documentation.

### 7.7 Mutual calls: preventing delegation loops

Your architecture is specifically `ApiA ↔ ApiB` — **bidirectional**. That creates a failure mode a one-way call graph does not have:

```
AppA → ApiA → (exchange) → ApiB → (exchange) → ApiA → (exchange) → ApiB → …
```

Each hop is individually valid. Nothing in OAuth stops it. Left unguarded it produces resource exhaustion, Okta rate-limit exhaustion (which takes down sign-in for *everyone*, not just the loop), and cascading timeouts.

Three defences, all of them cheap. Apply all three:

**1. Depth limiting.** Propagate a hop counter and refuse to delegate past it.

```csharp
public sealed class DelegationDepthHandler : DelegatingHandler
{
    public const string Header = "X-Delegation-Depth";
    private const int MaxDepth = 2;

    private readonly IHttpContextAccessor _ctx;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var inbound = 0;
        if (_ctx.HttpContext?.Request.Headers.TryGetValue(Header, out var raw) == true)
            int.TryParse(raw, out inbound);

        if (inbound >= MaxDepth)
            throw new DelegationDepthExceededException(
                $"Refusing outbound call at delegation depth {inbound}. " +
                "A service call graph this deep indicates a cycle (§7.7).");

        request.Headers.Add(Header, (inbound + 1).ToString());
        return await base.SendAsync(request, ct);
    }
}
```

**2. Correlation-ID cycle detection.** Flow a `traceparent` (W3C Trace Context) through every hop. A cycle shows up immediately in distributed tracing as a repeating span pattern under one trace ID — and it is the only way you will *find* a cycle that stays under the depth limit.

**3. Design the call graph acyclically.** The durable fix. If `ApiA` needs `ApiB`'s data and `ApiB` needs `ApiA`'s, that is usually a sign the boundary is drawn in the wrong place. Options, in order of preference: extract the shared concern into `ApiC` that both call; have one side publish events the other consumes; or accept the cycle and document the specific endpoints involved so a reviewer can check the depth guard is present.

> ⚠️ **Okta enforces org-wide rate limits on `/token`.** An uncontrolled delegation loop will not just fail — it can exhaust the org's token-endpoint budget and prevent *unrelated* applications and users from signing in. The depth limit is not a nicety; it is the blast-radius control that keeps a bug in one service from becoming a tenant-wide incident. Monitor Okta's `system.org.rate_limit.warning` System Log events (§14.1).

### 7.8 The rule to carry into every code review

> **A token is a bearer credential addressed to exactly one recipient.**
> Forwarding it to anyone else — however convenient, however internal, however "we're all behind the firewall" — hands that party a credential they can replay, and destroys the receiver's ability to tell an authorised call from an unauthorised one.
---

## 8. The WPF client

`AppA` and `AppB` are identical in structure and differ only in configuration. Build the authentication layer **once**, as a shared library, and reference it from both.

### 8.1 Solution layout

```
SSO.sln
├── src/
│   ├── Corp.Identity.Core/            ← shared; Microsoft packages only, no UI framework
│   │   ├── IAuthenticationService.cs
│   │   ├── OktaAuthenticationService.cs
│   │   ├── DpapiTokenStore.cs
│   │   ├── AccessTokenCache.cs
│   │   ├── OktaTokenHandler.cs
│   │   ├── OktaClientOptions.cs
│   │   ├── IdentityServiceCollectionExtensions.cs   ← AddCorpIdentity, the entry point
│   │   └── Protocol/                  ← the OIDC flow itself
│   │       ├── OpenIdConnectClient.cs
│   │       ├── LoopbackListener.cs
│   │       ├── IdentityTokenValidator.cs
│   │       └── Pkce.cs
│   ├── Corp.Identity.Wpf/             ← WPF only: dialogs, busy, focus, crash handling
│   │   ├── IUserInteraction.cs
│   │   ├── WpfUserInteraction.cs
│   │   ├── TelerikUserInteraction.cs
│   │   └── SessionExpiryNotifier.cs
│   ├── Corp.Identity.Prism/           ← OPTIONAL; the only third-party dependency
│   │   ├── AuthenticationModule.cs
│   │   ├── Authorization.cs           ← RequiresScope, AuthenticationNavigationGuard
│   │   └── PrismIdentityExtensions.cs
│   ├── AppA/                          ← thin: shell, modules, views
│   ├── AppB/
│   ├── Corp.Api.Security/             ← shared, referenced by both APIs
│   ├── ApiA/
│   └── ApiB/
└── tests/
```

> ⚠️ **Resist duplicating the auth code into each app.** It will diverge, and the divergence will be a security bug in whichever copy gets less attention. One library, two configurations.

### 8.2 Packages

```xml
<ItemGroup>
  <!-- OIDC/OAuth. Duende's OidcClient is the reference native-app client:
       standards-pure, PKCE by default, transport-agnostic browser hook. -->
  <PackageReference Include="Duende.IdentityModel.OidcClient" Version="7.1.0" />
  <PackageReference Include="Duende.IdentityModel" Version="8.1.0" />

  <PackageReference Include="Prism.DryIoc" Version="8.1.97" />
  <PackageReference Include="Microsoft.Extensions.Http" Version="8.0.0" />
  <PackageReference Include="Microsoft.Extensions.Options" Version="8.0.0" />
  <PackageReference Include="Microsoft.Extensions.Logging" Version="8.0.0" />
  <PackageReference Include="System.Security.Cryptography.ProtectedData" Version="8.0.0" />

  <PackageReference Include="Telerik.Windows.Controls.for.Wpf" Version="..." />
</ItemGroup>
```

> ⚠️ **The package was renamed.** `IdentityModel.OidcClient` and `IdentityModel` are gone from NuGet; they are now `Duende.IdentityModel.OidcClient` and `Duende.IdentityModel`. Older guides (and earlier drafts of this one) still cite the old names, which no longer resolve. The namespaces moved with them: `Duende.IdentityModel.OidcClient`, `Duende.IdentityModel.OidcClient.Browser`.

> **The implementation in this repository no longer uses OidcClient.** `Corp.Identity.Core`
> now speaks the protocol directly on `Microsoft.IdentityModel.Protocols.OpenIdConnect`,
> so the desktop stack has no dependency published by anyone but Microsoft — the packages
> are `Microsoft.IdentityModel.Protocols.OpenIdConnect`,
> `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.Extensions.*` and
> `System.Security.Cryptography.ProtectedData`. That matters where a third-party
> dependency needs sign-off before it can ship, and it is not a large amount of code:
> `ConfigurationManager<OpenIdConnectConfiguration>` supplies discovery, JWKS caching and
> key-rollover refresh, leaving PKCE, `state`/`nonce`, and the authorize/token/refresh
> calls — see `src/Corp.Identity.Core/Protocol/`.
>
> Okta publishes no OIDC client for .NET desktop at all: `Okta.AspNetCore` and
> `Okta.AspNet` are server-side middleware, `Okta.Sdk` is the management API, and
> `Okta.Xamarin` is mobile-only. There is no Okta-native option for WPF to choose.
>
> **The sections below still describe the OidcClient implementation.** They remain a
> correct account of the protocol and of what a library-based version looks like; where
> they differ from the code, the code in `Protocol/` is what runs.

**Why a standards library rather than the Okta .NET SDK:** the Okta client SDKs are thin wrappers over the same standards. Using the standards library directly means the code is portable to any OIDC provider, the samples in RFCs apply verbatim, and you can read exactly what is on the wire. Okta's own .NET guidance points at standard JWT validation for the API side ([JWT validation guide](https://developer.okta.com/code/dotnet/jwt-validation/)).

### 8.3 The contract

Everything the rest of the application knows about authentication:

```csharp
public interface IAuthenticationService
{
    bool IsAuthenticated { get; }

    /// <summary>Identity for the UI. Sourced from the ID TOKEN, never the access token.</summary>
    ClaimsPrincipal? User { get; }

    event EventHandler<AuthenticationStateChangedEventArgs>? StateChanged;

    /// <summary>Interactive sign-in via the system browser.</summary>
    Task<AuthenticationResult> SignInAsync(CancellationToken ct = default);

    /// <summary>Silent restore from a stored refresh token. Call at startup.</summary>
    Task<AuthenticationResult> TryRestoreSessionAsync(CancellationToken ct = default);

    /// <summary>
    /// A valid access token for one resource. Refreshes silently when needed.
    /// Callers pass a logical resource name, never a raw audience string.
    /// </summary>
    Task<string> GetAccessTokenAsync(string resourceName, CancellationToken ct = default);

    Task SignOutAsync(SignOutScope scope, CancellationToken ct = default);
}

public enum SignOutScope
{
    /// <summary>Discard local tokens only. The Okta session survives; the next launch is silent.</summary>
    Local,
    /// <summary>Also end the Okta session, signing the user out of every app. See §11.</summary>
    Global,
}
```

Two deliberate constraints in this interface:

- **No `AccessToken` property.** Exposing one invites a view model to grab it once and cache a stale copy. `GetAccessTokenAsync` is the only route, and it is always fresh.
- **`resourceName` is logical** (`"ApiA"`), not an audience URI. Audience strings live in configuration, in one place.

### 8.4 Configuration

`appsettings.json`, shipped alongside the executable. None of it is secret — a public client has no secrets — but it is environment-specific.

```json
{
  "Okta": {
    "Domain": "dev-12345678.okta.com",
    "ClientId": "0oa1a2b3c4d5e6f7g8h9",
    "Scopes": [ "openid", "profile", "email", "offline_access" ],
    "RedirectPorts": [ 8765, 8766, 8767 ],
    "RedirectPath": "/callback",
    "PostLogoutPath": "/signout-callback",
    "Resources": {
      "ApiA": {
        "AuthorizationServerId": "aus1a2b3c4d5e6f7g8h9",
        "Audience": "api://apia",
        "Scopes": [ "apia.read", "apia.write" ],
        "BaseAddress": "https://apia.contoso.internal/"
      }
    }
  }
}
```

> ⚠️ **`ClientId` is not a secret, but do not ship one config file to every environment.** A dev client ID pointed at a production Okta domain fails in confusing ways. Use per-environment transforms and assert at startup that `Domain` and `AuthorizationServerId` agree with the build configuration.

### 8.5 The loopback browser

The bridge between OidcClient and the real browser. Three responsibilities: bind a loopback port, launch the system browser, and capture the redirect.

```csharp
public sealed class LoopbackBrowser : IBrowser
{
    private readonly IReadOnlyList<int> _ports;
    private readonly string _path;
    private readonly ILogger<LoopbackBrowser> _log;

    public int? BoundPort { get; private set; }

    public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken ct)
    {
        using var listener = new HttpListener();
        var port = BindFirstAvailable(listener);
        BoundPort = port;

        try
        {
            Process.Start(new ProcessStartInfo(options.StartUrl) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Could not launch the system browser");
            return new BrowserResult
            {
                ResultType = BrowserResultType.UnknownError,
                Error = "No default browser is configured on this machine."
            };
        }

        // Bound wait: without this, an abandoned sign-in leaks a listener and a
        // port for the life of the process.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));

        try
        {
            var context = await listener.GetContextAsync().WaitAsync(timeout.Token);
            var result  = context.Request.Url!.Query;

            await WriteBrowserResponseAsync(context.Response);

            // Bring the WPF window back to the foreground — otherwise the user
            // is left staring at a browser tab wondering what happened (§8.8).
            Application.Current?.Dispatcher.Invoke(() =>
                Application.Current.MainWindow?.Activate());

            return new BrowserResult { ResultType = BrowserResultType.Success, Response = result };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new BrowserResult { ResultType = BrowserResultType.Timeout };
        }
    }

    private int BindFirstAvailable(HttpListener listener)
    {
        foreach (var port in _ports)
        {
            try
            {
                listener.Prefixes.Clear();
                listener.Prefixes.Add($"http://127.0.0.1:{port}{_path}/");
                listener.Start();
                _log.LogInformation("Loopback redirect listening on port {Port}", port);
                return port;
            }
            catch (HttpListenerException)
            {
                // Port taken — by another instance of this app, or another app.
            }
        }

        throw new InvalidOperationException(
            $"All registered loopback ports ({string.Join(", ", _ports)}) are in use. " +
            "Every port here must also be registered as a redirect URI in Okta (§6.5).");
    }

    private static async Task WriteBrowserResponseAsync(HttpListenerResponse response)
    {
        // Keep this self-contained: no external CSS, images, or fonts. The browser
        // may have no network route to your intranet at this moment.
        const string html = """
            <!doctype html><html><head><meta charset="utf-8">
            <title>Signed in</title>
            <style>
              body{font-family:Segoe UI,system-ui,sans-serif;display:grid;
                   place-items:center;height:100vh;margin:0;color:#1a1a1a}
              .c{text-align:center}h1{font-size:1.25rem;font-weight:600}
              p{color:#555;font-size:.9rem}
            </style></head><body><div class="c">
            <h1>Signed in successfully</h1>
            <p>You can close this tab and return to the application.</p>
            </div><script>setTimeout(()=>window.close(),2000)</script>
            </body></html>
            """;

        var bytes = Encoding.UTF8.GetBytes(html);
        response.ContentType     = "text/html; charset=utf-8";
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }
}
```

> ⚠️ **`HttpListener` on Windows needs no URL ACL for `127.0.0.1` on a high port** running as the interactive user, so no elevation is required. It **does** fail if a host firewall blocks loopback binds — rare, but present in some hardened SOE images. Detect it at startup and surface a clear message rather than a generic sign-in failure.

> ⚠️ **The `state` parameter is your CSRF defence, and OidcClient generates and validates it for you.** If you ever hand-roll this flow, verify `state` matches what you sent, before doing anything else with the response.

### 8.6 Token storage: DPAPI

```csharp
public sealed class DpapiTokenStore : ITokenStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Corp.Identity.Client.v1");

    private readonly string _path;

    public DpapiTokenStore(IOptions<OktaClientOptions> options)
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Corp", options.Value.ApplicationName);
        Directory.CreateDirectory(dir);

        // Per client_id: AppA and AppB must never read each other's tokens (§4.7).
        _path = Path.Combine(dir, $"{options.Value.ClientId}.tokens");
    }

    public async Task SaveAsync(StoredTokens tokens, CancellationToken ct = default)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(tokens);
        var encrypted = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);

        // Write-then-move: a crash mid-write must not leave a truncated file
        // that forces a re-authentication on next launch.
        var tmp = _path + ".tmp";
        await File.WriteAllBytesAsync(tmp, encrypted, ct);
        File.Move(tmp, _path, overwrite: true);

        CryptographicOperations.ZeroMemory(plaintext);
    }

    public async Task<StoredTokens?> LoadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(_path)) return null;

        try
        {
            var encrypted = await File.ReadAllBytesAsync(_path, ct);
            var plaintext = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            try     { return JsonSerializer.Deserialize<StoredTokens>(plaintext); }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            // Roaming profile moved, machine rebuilt, or the file was tampered
            // with. Unrecoverable and not an error: delete and re-authenticate.
            Clear();
            return null;
        }
    }

    public void Clear()
    {
        try { if (File.Exists(_path)) File.Delete(_path); } catch { /* best effort */ }
    }
}
```

**What DPAPI `CurrentUser` scope actually gives you.** The blob is decryptable only by the same Windows user on the same machine (or anywhere their roaming profile and master key reach). This defeats: another user on a shared machine, a stolen laptop with the disk pulled, a file copied to a share, an over-broad backup.

> ⚠️ **Be honest about the limit.** DPAPI does **not** defend against malware running as the signed-in user — that code can call `Unprotect` exactly as you do. No in-process technique on a general-purpose desktop OS changes this. What actually contains the damage is elsewhere: **short access-token lifetimes**, **rotating refresh tokens with reuse detection** (§5.6), and **DPoP sender-constraining** (§12.4). Treat DPAPI as raising the cost of casual theft, not as a boundary.

### 8.7 The authentication service

```csharp
public sealed class OktaAuthenticationService : IAuthenticationService, IDisposable
{
    private readonly OktaClientOptions _options;
    private readonly ITokenStore _store;
    private readonly IAccessTokenCache _accessTokens;
    private readonly ILogger<OktaAuthenticationService> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private OidcClient? _oidc;
    private StoredTokens? _tokens;

    public bool IsAuthenticated => User?.Identity?.IsAuthenticated == true;
    public ClaimsPrincipal? User { get; private set; }
    public event EventHandler<AuthenticationStateChangedEventArgs>? StateChanged;

    private OidcClient CreateClient(ResourceOptions resource, LoopbackBrowser browser)
    {
        var port = _options.RedirectPorts[0];

        return new OidcClient(new OidcClientOptions
        {
            Authority    = $"https://{_options.Domain}/oauth2/{resource.AuthorizationServerId}",
            ClientId     = _options.ClientId,
            RedirectUri  = $"http://127.0.0.1:{port}{_options.RedirectPath}",
            PostLogoutRedirectUri = $"http://127.0.0.1:{port}{_options.PostLogoutPath}",
            Scope        = string.Join(' ', _options.Scopes.Concat(resource.Scopes)),
            Browser      = browser,

            // Public client: PKCE only, no secret. This is the default, set
            // explicitly so nobody "adds the missing secret" later.
            ClientSecret = null,

            Policy = new Policy
            {
                // Renamed in OidcClient 7.x (was RequireIdentityTokenSignatureVerification).
                RequireIdentityTokenSignature = true,
                ValidateTokenIssuerName = true,
                ValidateTokenIssuerName = true,
            },
        });
    }

    public async Task<AuthenticationResult> SignInAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var browser  = new LoopbackBrowser(_options.RedirectPorts, _options.RedirectPath, _log);
            var resource = _options.Resources.Values.First();
            _oidc = CreateClient(resource, browser);

            var result = await _oidc.LoginAsync(new LoginRequest(), ct);

            if (result.IsError)
            {
                _log.LogWarning("Sign-in failed: {Error} {Description}",
                                result.Error, result.ErrorDescription);
                return AuthenticationResult.Failed(result.Error, result.ErrorDescription);
            }

            _tokens = StoredTokens.From(result);
            await _store.SaveAsync(_tokens, ct);

            _accessTokens.Set(resource.Name, result.AccessToken, result.AccessTokenExpiration);

            // Identity comes from the ID token (§3.2). OidcClient has already
            // validated its signature, issuer, audience, and nonce.
            User = result.User;
            RaiseStateChanged(AuthenticationChangeReason.SignedIn);

            return AuthenticationResult.Success(result.User);
        }
        finally { _gate.Release(); }
    }

    public async Task<AuthenticationResult> TryRestoreSessionAsync(CancellationToken ct = default)
    {
        _tokens = await _store.LoadAsync(ct);
        if (_tokens?.RefreshToken is null)
            return AuthenticationResult.NoSession();

        try
        {
            await RefreshAsync(_options.Resources.Values.First(), ct);
            RaiseStateChanged(AuthenticationChangeReason.SessionRestored);
            return AuthenticationResult.Success(User!);
        }
        catch (RefreshFailedException ex)
        {
            // Expected and routine: refresh token expired, was rotated out,
            // revoked by an admin, or the user was deprovisioned. Not an error
            // condition — just means an interactive sign-in is required.
            _log.LogInformation("Session could not be restored ({Reason}); sign-in required",
                                ex.OktaError);
            _store.Clear();
            return AuthenticationResult.NoSession();
        }
    }

    public async Task<string> GetAccessTokenAsync(string resourceName, CancellationToken ct = default)
    {
        if (_accessTokens.TryGet(resourceName, out var token))
            return token;

        await _gate.WaitAsync(ct);
        try
        {
            // Re-check: a concurrent caller may have refreshed while we waited.
            if (_accessTokens.TryGet(resourceName, out token))
                return token;

            var resource = _options.Resources[resourceName];
            return await RefreshAsync(resource, ct);
        }
        finally { _gate.Release(); }
    }
}
```

> ⚠️ **The `SemaphoreSlim` is not optional.** A Prism shell routinely fires several view models' data loads on navigation. Without serialisation they race into simultaneous refresh calls with the *same* rotating refresh token — and with rotation enabled, the second one presents an already-rotated token. Okta reads that as replay and can invalidate the whole family, signing the user out for no reason. Refresh must be single-flight, and the double-check inside the lock is what makes it cheap.

### 8.8 Refresh, rotation, and proactive renewal

```csharp
private async Task<string> RefreshAsync(ResourceOptions resource, CancellationToken ct)
{
    if (_tokens?.RefreshToken is null)
        throw new RefreshFailedException("no_refresh_token");

    var oidc   = _oidc ??= CreateClient(resource, new LoopbackBrowser(
                                _options.RedirectPorts, _options.RedirectPath, _log));
    var result = await oidc.RefreshTokenAsync(_tokens.RefreshToken, cancellationToken: ct);

    if (result.IsError)
        throw new RefreshFailedException(result.Error, result.ErrorDescription);

    // Rotation: Okta returns a NEW refresh token and invalidates the old one.
    // Persisting it immediately is critical — if the process dies between the
    // response and the write, the stored token is already dead and the user
    // faces an unexplained sign-in on next launch.
    _tokens = _tokens with
    {
        RefreshToken = result.RefreshToken,
        AccessToken  = result.AccessToken,
        ExpiresAt    = result.AccessTokenExpiration,
    };
    await _store.SaveAsync(_tokens, ct);

    _accessTokens.Set(resource.Name, result.AccessToken, result.AccessTokenExpiration);
    return result.AccessToken;
}
```

The access-token cache renews **before** expiry rather than after a 401 — a proactive refresh is invisible; a reactive one costs the user a failed request:

```csharp
public sealed class AccessTokenCache : IAccessTokenCache
{
    // Renew this far ahead of exp. Covers clock skew between the desktop and
    // the API host, plus the round trip itself.
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(90);

    private readonly ConcurrentDictionary<string, Entry> _entries = new();

    public bool TryGet(string resource, out string token)
    {
        token = string.Empty;
        if (!_entries.TryGetValue(resource, out var e)) return false;
        if (DateTimeOffset.UtcNow >= e.ExpiresAt - Skew)
        {
            _entries.TryRemove(resource, out _);
            return false;
        }
        token = e.Token;
        return true;
    }

    public void Set(string resource, string token, DateTimeOffset expiresAt)
        => _entries[resource] = new Entry(token, expiresAt);

    public void Clear() => _entries.Clear();

    private readonly record struct Entry(string Token, DateTimeOffset ExpiresAt);
}
```

> ⚠️ **Desktop machines sleep.** A laptop closed at 17:00 and reopened at 09:00 resumes with timers that have not fired and a refresh token that may have aged past its idle window. Subscribe to `SystemEvents.PowerModeChanged` (`PowerModes.Resume`) and re-run `TryRestoreSessionAsync`, so the user hits a clean sign-in prompt rather than a wall of failed requests.

### 8.9 Getting tokens for a second API

Only needed if the WPF app calls **both** APIs directly. In the baseline architecture — `AppA → ApiA`, `AppB → ApiB`, with cross-API traffic handled server-side by §7 — it is not needed at all. It **is** needed for §7 Pattern 3.

The mechanics differ by topology, and this is a real trade-off that §5.2 flagged:

**Variant A (one AS, two audiences).** The existing refresh token works for both audiences. Add the `resource` parameter ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)) to the refresh request — no browser, no user interaction:

```csharp
var response = await _http.RequestRefreshTokenAsync(new RefreshTokenRequest
{
    Address      = $"https://{_options.Domain}/oauth2/{asId}/v1/token",
    ClientId     = _options.ClientId,
    RefreshToken = _tokens.RefreshToken,
    Scope        = "apib.read",
    Parameters   = { { "resource", "api://apib" } },
});
```

**Variant B (one AS per API).** Refresh tokens are scoped to their issuing authorization server, so a token from `apia-as` is useless at `apib-as`. `AppA` must run a **second authorization request** against `apib-as`. It will complete silently — the Okta session cookie is already in the browser — but it is a browser round trip, not a background HTTP call:

```csharp
var result = await CreateClient(_options.Resources["ApiB"], browser)
    .LoginAsync(new LoginRequest
    {
        FrontChannelExtraParameters = { { "prompt", "none" } }   // fail rather than prompt
    }, ct);

if (result.IsError && result.Error is "login_required" or "interaction_required")
{
    // The Okta session lapsed. Retry without prompt=none to sign in interactively.
    result = await CreateClient(_options.Resources["ApiB"], browser)
        .LoginAsync(new LoginRequest(), ct);
}
```

`prompt=none` is what makes this safe to attempt automatically: Okta either completes silently or returns `login_required`, and never surprises the user with an unexpected browser window mid-workflow.

> **Choosing between the variants, revisited.** If your WPF apps only ever call their own API, **Variant B costs you nothing and is strictly better** (§5.2). If a client must call several APIs, Variant A's single refresh token is genuinely more convenient — weigh that against the EA dependency. Do not decide this from the diagram alone; enumerate which client calls which API first.

### 8.10 Attaching tokens to outbound calls

A `DelegatingHandler` keeps every view model and repository ignorant of tokens entirely:

```csharp
public sealed class OktaTokenHandler : DelegatingHandler
{
    private const string RetryMarker = "X-Corp-Auth-Retried";

    private readonly IAuthenticationService _auth;
    private readonly string _resourceName;
    private readonly ILogger<OktaTokenHandler> _log;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var token = await _auth.GetAccessTokenAsync(_resourceName, ct);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await base.SendAsync(request, ct);

        if (response.StatusCode != HttpStatusCode.Unauthorized ||
            request.Headers.Contains(RetryMarker))
            return response;

        // A 401 despite a locally-valid token: revoked, key rotated, or clock
        // skew. Force one refresh and retry exactly once — never loop.
        _log.LogInformation("401 from {Resource}; forcing token refresh and retrying once",
                            _resourceName);
        response.Dispose();

        _auth.InvalidateAccessToken(_resourceName);
        var fresh = await _auth.GetAccessTokenAsync(_resourceName, ct);

        // An HttpRequestMessage cannot be sent twice — clone it, including the
        // body, which must be buffered to be replayable.
        var retry = await CloneAsync(request, ct);
        retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fresh);
        retry.Headers.Add(RetryMarker, "1");

        return await base.SendAsync(retry, ct);
    }

    private static async Task<HttpRequestMessage> CloneAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version
        };

        if (request.Content is not null)
        {
            var buffer = await request.Content.ReadAsByteArrayAsync(ct);
            clone.Content = new ByteArrayContent(buffer);
            foreach (var h in request.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }

        foreach (var h in request.Headers)
            clone.Headers.TryAddWithoutValidation(h.Key, h.Value);
        foreach (var p in request.Options)
            clone.Options.Set(new HttpRequestOptionsKey<object?>(p.Key), p.Value);

        return clone;
    }
}
```

Registration:

```csharp
services.AddHttpClient<IApiAClient, ApiAClient>(c =>
        c.BaseAddress = new Uri(options.Resources["ApiA"].BaseAddress))
    .AddHttpMessageHandler(sp => new OktaTokenHandler(
        sp.GetRequiredService<IAuthenticationService>(),
        resourceName: "ApiA",
        sp.GetRequiredService<ILogger<OktaTokenHandler>>()))
    .AddPolicyHandler(HttpPolicyExtensions
        .HandleTransientHttpError()
        .WaitAndRetryAsync(3, n => TimeSpan.FromMilliseconds(200 * Math.Pow(2, n))));
```

> ⚠️ **Order matters: the token handler must run *inside* the retry policy.** If Polly wraps the token handler, a retry re-uses the original request object and the already-attached (possibly expired) token. `AddHttpMessageHandler` before `AddPolicyHandler` gives the correct nesting.

> ⚠️ **The retry marker is what prevents an infinite 401 loop.** If the API rejects tokens for a reason refreshing cannot fix — a misconfigured audience, say — an unmarked handler will refresh-and-retry forever, hammering both Okta and the API. Exactly one retry, always.

### 8.11 Prism 8 wiring

```csharp
public partial class App : PrismApplication
{
    protected override Window CreateShell() => Container.Resolve<ShellWindow>();

    protected override void RegisterTypes(IContainerRegistry registry)
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{Env.Current}.json", optional: true)
            .Build();

        registry.RegisterInstance<IConfiguration>(config);
        registry.RegisterSingleton<ITokenStore, DpapiTokenStore>();
        registry.RegisterSingleton<IAccessTokenCache, AccessTokenCache>();
        registry.RegisterSingleton<IAuthenticationService, OktaAuthenticationService>();
        registry.RegisterSingleton<SessionExpiryNotifier>();

        // Prism dialogs rendered as Telerik RadWindows (§8.12).
        registry.RegisterDialogWindow<TelerikDialogWindow>();
        registry.RegisterDialog<SignInPromptView, SignInPromptViewModel>();
        registry.RegisterDialog<SessionExpiredView, SessionExpiredViewModel>();
    }

    protected override void ConfigureModuleCatalog(IModuleCatalog catalog)
    {
        // Authentication loads first and unconditionally — every other module
        // may assume an IAuthenticationService is present and initialised.
        catalog.AddModule<AuthenticationModule>(InitializationMode.WhenAvailable);
        catalog.AddModule<OrdersModule>(InitializationMode.OnDemand);
    }

    protected override async void OnInitialized()
    {
        var auth  = Container.Resolve<IAuthenticationService>();
        var shell = Container.Resolve<ShellWindow>();

        ((ShellViewModel)shell.DataContext).IsBusy = true;
        try
        {
            // Silent restore. Only prompt if it fails.
            var restored = await auth.TryRestoreSessionAsync();
            if (!restored.Succeeded)
            {
                var signedIn = await auth.SignInAsync();
                if (!signedIn.Succeeded)
                {
                    Container.Resolve<IDialogService>()
                             .ShowDialog(nameof(SignInPromptView));
                    Current.Shutdown();
                    return;
                }
            }
        }
        finally
        {
            ((ShellViewModel)shell.DataContext).IsBusy = false;
        }

        Container.Resolve<SessionExpiryNotifier>().Start();
        base.OnInitialized();
    }
}
```

> ⚠️ **Do not authenticate in the `ShellViewModel` constructor.** Constructors cannot await, so you get either a deadlock from `.Result` or a fire-and-forget that renders an unauthenticated shell for a few frames. `OnInitialized` is the correct hook — the container is built and the shell exists, but nothing has navigated yet.

### 8.12 Telerik integration

**Prism dialogs as `RadWindow`.** Prism's `IDialogService` needs an `IDialogWindow`; the default is a plain `Window` that will not match your Telerik theme:

```csharp
public partial class TelerikDialogWindow : RadWindow, IDialogWindow
{
    public TelerikDialogWindow()
    {
        InitializeComponent();
        Header = "Corp";
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
    }

    public IDialogResult? Result { get; set; }
}
```

**Theme, applied before any window is created:**

```csharp
protected override void OnStartup(StartupEventArgs e)
{
    StyleManager.ApplicationTheme = new FluentTheme();
    base.OnStartup(e);
}
```

**Busy indicator during the browser hand-off.** The single biggest UX complaint about correct native SSO is that focus jumps to the browser and the app appears frozen. Address it in the shell — never by moving to WebView2 (§4.2):

```xml
<telerik:RadBusyIndicator IsBusy="{Binding IsBusy}"
                          BusyContent="{Binding BusyMessage}"
                          IsIndeterminate="True">
    <ContentControl prism:RegionManager.RegionName="{x:Static inf:Regions.Main}" />
</telerik:RadBusyIndicator>
```

Set `BusyMessage` to something that explains the browser rather than describing the mechanism: *"Complete sign-in in your browser, then return here."*

**Session expiry warning** via `RadDesktopAlert`, a few minutes before the refresh token's idle window elapses — so a user who steps away comes back to a warning rather than a wall of failed requests:

```csharp
public sealed class SessionExpiryNotifier
{
    public void Start()
    {
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(1) };
        _timer.Tick += (_, _) =>
        {
            if (_auth.TimeUntilSessionExpiry() > TimeSpan.FromMinutes(5)) return;

            RadDesktopAlertManager.Instance.ShowAlert(new DesktopAlertParameters
            {
                Header    = "Session expiring",
                Content   = "Your sign-in expires in under five minutes.",
                ShowDuration = 10_000,
            });
        };
        _timer.Start();
    }
}
```

### 8.13 Gating navigation

Authentication gates the app; **authorization** gates individual screens. Enforce it at navigation time so an unauthorised view is never constructed:

```csharp
[AttributeUsage(AttributeTargets.Class)]
public sealed class RequiresScopeAttribute(params string[] scopes) : Attribute
{
    public IReadOnlyList<string> Scopes { get; } = scopes;
}

public sealed class AuthenticationNavigationGuard
{
    public void Attach(IRegionNavigationService navigation)
        => navigation.Navigating += OnNavigating;

    private void OnNavigating(object? sender, RegionNavigationEventArgs e)
    {
        var viewType = _viewResolver.Resolve(e.Uri);
        var required = viewType?.GetCustomAttribute<RequiresScopeAttribute>();
        if (required is null) return;

        if (!_auth.IsAuthenticated || !required.Scopes.All(_auth.HasScope))
        {
            e.Cancel();
            RadWindow.Alert(new DialogParameters
            {
                Header  = "Access denied",
                Content = "You do not have permission to open this screen.",
            });
        }
    }
}
```

> ⚠️ **Client-side gating is UX, not security.** It stops a user opening a screen they cannot use. It stops nothing else — a modified client, or a plain `curl`, bypasses it entirely. **Every rule enforced here must be enforced again in the API** (§9.3). The client hides the button; the server refuses the request. Only the second one is a control.
---

## 9. The ASP.NET Core APIs

An API's job in this architecture is narrow and should stay that way: **verify the token, then authorize the operation.** It never calls Okta on the request path.

### 9.1 Packages and options

```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.*" />
<PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="8.0.*" />
```

```json
{
  "Okta": {
    "Issuer": "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
    "Audience": "api://apia",
    "Downstream": {
      "ApiB": {
        "BaseAddress": "https://apib.contoso.internal/",
        "Audience": "api://apib",
        "Scopes": "apib.read"
      }
    },
    "Service": {
      "ClientId": "0oa9z8y7x6w5v4u3t2s1",
      "Issuer": "https://dev-12345678.okta.com/oauth2/aus9z8y7x6w5v4u3t2s1",
      "SigningCertificateThumbprint": "A1B2C3D4E5F6..."
    }
  }
}
```

### 9.2 Token validation — the security-critical configuration

```csharp
var okta = builder.Configuration.GetSection("Okta").Get<OktaApiOptions>()!;

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Discovers issuer metadata and the JWKS from
        // {Authority}/.well-known/openid-configuration. Fetched at first use,
        // cached, and refreshed automatically on key rollover.
        options.Authority = okta.Issuer;
        options.Audience  = okta.Audience;

        // Keep Okta's claim names as they appear on the wire. Without this,
        // ASP.NET Core rewrites 'sub' to the long WS-Fed nameidentifier URI
        // and your claim lookups silently return nothing.
        options.MapInboundClaims = false;

        options.RequireHttpsMetadata = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = okta.Issuer,

            // Rule 1 (§3.3). This single line is what stops a token minted for
            // ApiB — or an ID token minted for AppA — being accepted here.
            ValidateAudience         = true,
            ValidAudience            = okta.Audience,

            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,

            // Pin the algorithm. Prevents 'alg' confusion and any attempt to
            // present an unsigned or symmetric-keyed token.
            ValidAlgorithms          = new[] { SecurityAlgorithms.RsaSha256 },

            // Default is 5 minutes, which is far too generous when access
            // tokens live 15. Requires NTP on the API hosts (§13.5).
            ClockSkew                = TimeSpan.FromSeconds(30),

            NameClaimType            = "sub",
            RoleClaimType            = "groups",
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = ctx =>
            {
                // Log the failure REASON, never the token.
                ctx.NoResult();
                var log = ctx.HttpContext.RequestServices
                             .GetRequiredService<ILogger<Program>>();
                log.LogWarning("Token rejected: {Type}: {Message}",
                               ctx.Exception.GetType().Name, ctx.Exception.Message);
                return Task.CompletedTask;
            },

            OnChallenge = ctx =>
            {
                // RFC 6750 §3: tell the client WHY, without leaking internals.
                ctx.Response.Headers.WWWAuthenticate =
                    $"Bearer realm=\"{okta.Audience}\", error=\"invalid_token\"";
                return Task.CompletedTask;
            },
        };
    });
```

> ⚠️ **Never set `ValidateAudience = false`.** It appears in a great many samples and in most "just make it work" Stack Overflow answers. Turning it off means your API accepts *any* token your Okta org ever issued — for any other API, for any other client, and ID tokens too. It converts every other application in the tenant into a path into this one, and it is the enabling condition for the §7.5 anti-pattern. Make it a build-breaking rule (§15.2).

> ⚠️ **`RequireHttpsMetadata = true` in every environment, including development.** The metadata document contains the public keys used to validate every token. Fetching it over plaintext HTTP means an attacker on the path can substitute their own keys and mint tokens your API will happily accept.

> ⚠️ **`MapInboundClaims = false` is a correctness fix, not a preference.** With the default (`true`), `sub` becomes `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. Code that looks up `"sub"` finds nothing, returns null, and — depending on how it is written — either crashes or falls through to an unauthenticated path. This has been the root cause of real authorization bypasses.

### 9.3 Scope and role authorization

Okta emits `scp` as a JSON array (§3.4), which .NET surfaces as multiple claims. This helper handles both that and the space-delimited form other IdPs use, so the code survives a provider change:

```csharp
public static class ClaimsPrincipalExtensions
{
    public static bool HasScope(this ClaimsPrincipal user, string scope)
        => user.FindAll("scp")
               .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
               .Contains(scope, StringComparer.Ordinal);

    public static string? OktaUserId(this ClaimsPrincipal user)
        => user.FindFirst("uid")?.Value;      // stable; prefer over 'sub' (§3.4)

    public static string? CallingClientId(this ClaimsPrincipal user)
        => user.FindFirst("cid")?.Value;

    /// <summary>True when the token has no user — a client-credentials token (§7.2).</summary>
    public static bool IsServicePrincipal(this ClaimsPrincipal user)
        => user.FindFirst("sub") is null || user.FindFirst("uid") is null;
}
```

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("apia.read",  p => p.RequireAuthenticatedUser()
                                          .RequireAssertion(c => c.User.HasScope("apia.read")));
    options.AddPolicy("apia.write", p => p.RequireAuthenticatedUser()
                                          .RequireAssertion(c => c.User.HasScope("apia.write")));

    // Group-derived roles. Scope says "this token may write"; the group says
    // "this person may approve". Both must hold.
    options.AddPolicy("ApproveInvoices", p => p.RequireAuthenticatedUser()
                                               .RequireAssertion(c => c.User.HasScope("apia.write"))
                                               .RequireRole("App-Finance"));

    // Deny by default: every endpoint requires an authenticated principal
    // unless it explicitly opts out with [AllowAnonymous].
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});
```

> ⚠️ **Set a `FallbackPolicy`.** Without it, a newly added controller with a forgotten `[Authorize]` is wide open, and nothing in the build or the tests will tell you. With it, the failure mode inverts: a forgotten attribute produces a 401 that someone notices in five minutes, instead of an unauthenticated endpoint nobody notices for a year.

```csharp
[ApiController]
[Route("orders")]
public sealed class OrdersController : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "apia.read")]
    public async Task<IActionResult> List(CancellationToken ct) { /* ... */ }

    [HttpPost("{id:guid}/approve")]
    [Authorize(Policy = "ApproveInvoices")]
    public async Task<IActionResult> Approve(Guid id, CancellationToken ct) { /* ... */ }
}
```

> ⚠️ **Scopes are necessary but never sufficient.** `apia.write` says the *token* is permitted to mutate `ApiA`. It says nothing about whether **this user** may mutate **this record**. Resource-level checks — does Alice own order 42? is it in her business unit? — must happen inside the handler, against your own data. No IdP can make that decision for you, and no amount of scope granularity substitutes for it.

### 9.4 JWKS caching and resilience

`AddJwtBearer` handles key retrieval, caching, and rollover through `ConfigurationManager`. Two defaults are worth tuning for a production API:

```csharp
options.RefreshInterval           = TimeSpan.FromHours(6);   // proactive refresh
options.AutomaticRefreshInterval  = TimeSpan.FromHours(12);  // hard maximum staleness
```

Behaviour worth knowing, because it shapes your Okta-outage story:

- Metadata is fetched on the **first request**, not at startup. The first request after a cold start pays that latency, and if Okta is unreachable at that moment it fails. Warm it explicitly during startup rather than discovering this in production:

```csharp
// Fail fast and loudly at startup if Okta metadata is unreachable, rather than
// failing the first user request several minutes later.
var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var opts = scope.ServiceProvider
        .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
        .Get(JwtBearerDefaults.AuthenticationScheme);

    try
    {
        await opts.ConfigurationManager!.GetConfigurationAsync(CancellationToken.None);
        app.Logger.LogInformation("Okta metadata loaded from {Authority}", opts.Authority);
    }
    catch (Exception ex)
    {
        app.Logger.LogCritical(ex, "Cannot reach Okta metadata at {Authority}. " +
            "Check egress rules and TLS interception (§13.4).", opts.Authority);
        throw;
    }
}
```

- On encountering an **unknown `kid`**, `ConfigurationManager` refreshes the metadata — but it is rate-limited (roughly once per 5 minutes by default) precisely so a flood of bogus `kid`s cannot be used to hammer Okta through your API. Do not defeat this by refreshing manually per request.
- Once cached, keys survive an Okta outage. Already-issued tokens keep validating; only new sign-ins fail. **This is the single most valuable availability property of the design** — say it out loud in your resilience review, because it is not obvious to people expecting a per-request IdP dependency.

### 9.5 Wiring the outbound call to `ApiB`

Bring §7 into the request pipeline. The pattern chosen there determines only which token source is injected — the handler shape is identical:

```csharp
// Pattern 1 — On-Behalf-Of
public sealed class OboTokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _ctx;
    private readonly OktaTokenExchangeService _exchange;
    private readonly DownstreamOptions _downstream;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var incoming = await _ctx.HttpContext!.GetTokenAsync("access_token")
            ?? throw new InvalidOperationException(
                   "No inbound access token. OBO requires a user-initiated request; " +
                   "for background work use client credentials (§7.2).");

        var delegated = await _exchange.ExchangeAsync(
            subjectToken: incoming,
            audience:     _downstream.Audience,
            scope:        _downstream.Scopes,
            ct);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", delegated);
        return await base.SendAsync(request, ct);
    }
}
```

```csharp
builder.Services.AddHttpContextAccessor();

// The named client used for USER-initiated calls.
builder.Services.AddHttpClient<IApiBClient, ApiBClient>(c =>
        c.BaseAddress = new Uri(okta.Downstream["ApiB"].BaseAddress))
    .AddHttpMessageHandler<OboTokenHandler>()
    .AddHttpMessageHandler<DelegationDepthHandler>()   // §7.7
    .AddPolicyHandler(HttpPolicyExtensions.HandleTransientHttpError()
        .WaitAndRetryAsync(3, n => TimeSpan.FromMilliseconds(200 * Math.Pow(2, n))))
    .AddPolicyHandler(HttpPolicyExtensions.HandleTransientHttpError()
        .CircuitBreakerAsync(5, TimeSpan.FromSeconds(30)));

// A SEPARATE named client for BACKGROUND work, with a service identity.
builder.Services.AddHttpClient<IApiBBackgroundClient, ApiBBackgroundClient>(c =>
        c.BaseAddress = new Uri(okta.Downstream["ApiB"].BaseAddress))
    .AddHttpMessageHandler<ClientCredentialsTokenHandler>();
```

> ⚠️ **Register the two clients separately, and name them so the difference is obvious.** The most damaging mistake available in §7 is using the service-identity client to serve a user-initiated request: `ApiB` then authorises the *service*, the user's own permissions are never checked, and every user silently gains the union of what the service may do. Two distinct typed clients, `IApiBClient` and `IApiBBackgroundClient`, makes that mistake visible at every call site instead of buried in a handler.

> ⚠️ **`GetTokenAsync("access_token")` returns null unless you ask for it.** Set `options.SaveToken = true` on the JwtBearer scheme, or read the raw token from the `Authorization` header yourself. Silent null here is a common half-hour of confusion.

### 9.6 Error responses

Return the right status, and never leak internals to the caller:

| Condition | Status | `WWW-Authenticate` |
|---|---|---|
| No token | `401` | `Bearer realm="api://apia"` |
| Expired / bad signature / wrong audience | `401` | `Bearer error="invalid_token"` |
| Valid token, missing scope | `403` | `Bearer error="insufficient_scope", scope="apia.write"` |
| Valid token and scope, but not permitted on *this* record | `403` | *(none — this is an app decision, not a token one)* |

The 401/403 distinction is not pedantry, it drives client behaviour: a `401` tells `AppA` to refresh its token and retry (§8.10); a `403` tells it the token is fine and retrying is pointless. Returning 401 for an authorization failure sends the client into a pointless refresh loop.

```csharp
app.UseExceptionHandler(b => b.Run(async ctx =>
{
    var feature = ctx.Features.Get<IExceptionHandlerFeature>();

    var (status, title) = feature?.Error switch
    {
        DelegationDepthExceededException => (StatusCodes.Status508LoopDetected,
                                             "Delegation cycle detected"),
        TokenExchangeException           => (StatusCodes.Status502BadGateway,
                                             "Downstream authorization failed"),
        _                                => (StatusCodes.Status500InternalServerError,
                                             "An unexpected error occurred"),
    };

    // ProblemDetails, RFC 7807. No stack traces, no token fragments, no
    // Okta error bodies — those go to the log, keyed by traceId (§14.2).
    await Results.Problem(title: title, statusCode: status,
                          extensions: new Dictionary<string, object?>
                          {
                              ["traceId"] = Activity.Current?.Id ?? ctx.TraceIdentifier
                          })
                 .ExecuteAsync(ctx);
}));
```

---

## 10. Cross-app SSO between AppA and AppB

The requirement: a user who signed into `AppA` this morning opens `AppB` and is **not prompted**.

### 10.1 Primary mechanism: the Okta browser session

Nothing extra to configure — it is a consequence of the choices already made in §4.2 and §4.3.

```
09:00  AppA  →  system browser  →  Okta /authorize
                                   no session → credentials + MFA
                                   ┌──────────────────────────────┐
                                   │ Okta sets its session cookie │
                                   │ in the SYSTEM BROWSER        │
                                   └──────────────────────────────┘
                                   → code → AppA's tokens

12:30  AppB  →  same system browser  →  Okta /authorize
                                   cookie present, session valid
                                   → code, NO PROMPT
                                   → AppB's own tokens
```

The user sees a browser window flash open and close. That flash is the entire mechanism.

**Session lifetime is what actually governs the experience.** Configure it in **Security → Global Session Policy** (Identity Engine):

| Setting | Suggested | Effect |
|---|---|---|
| Maximum session lifetime | 8–12 hours | Covers a working day; forces daily re-auth |
| Session idle timeout | 2 hours | Unattended machines lapse |
| Persist session cookie across browser restarts | ✅ Enabled | Otherwise closing the browser kills SSO |

> ⚠️ **"Persist session cookie across browser restarts" is the single setting that decides whether desktop SSO works in practice.** Disabled, the Okta session cookie is a *browser-session* cookie: it dies when the user closes their last browser window — something desktop users do constantly, without any notion that it affects their applications. `AppB` then prompts, users report "SSO is broken", and the cause is nowhere near the application code. **Verify this setting before debugging anything in your client.**

**Reducing the flash further.** Pass `prompt=none` on a first attempt so the request either completes silently or fails cleanly with `login_required` (§8.9), then retry interactively only if needed. This gives you a genuinely non-interactive path in the common case and a clean fallback otherwise.

### 10.2 What to tell users

Two behaviours will generate support tickets unless you get ahead of them:

1. **"A browser window flashed."** Expected — that is the security model working, and the reason nobody can phish them through a fake in-app login form. Worth one line in release notes.
2. **"I have to sign in again after closing Chrome."** That is the persistent-cookie setting in §10.1, not an application bug.

### 10.3 Upgrade path: Okta Native SSO

If the browser flash is unacceptable — a kiosk, a locked-down terminal, a genuinely browser-free requirement — Okta Native SSO removes the browser from the *second* app entirely. `AppA` signs in once with a browser; `AppB` exchanges a device secret for its own tokens with no browser at all. Fully documented in [Appendix A](#appendix-a--okta-native-sso).

Adopt it when the browser round trip is a genuine business problem, not merely because a silent flow sounds tidier. It adds a device secret to store and revoke, requires a feature enabled on your org, and constrains both apps to compatible assurance policies.

### 10.4 Zero-prompt: Okta Desktop SSO

For a fully seamless experience — user logs into Windows, opens `AppA`, is signed in with no prompt and no visible browser interaction — Okta offers **Desktop SSO** (IWA/Kerberos via the Okta IWA Web agent) and **Okta FastPass** via Okta Verify.

This is an **infrastructure prerequisite, not application code**: it requires domain-joined machines, an agent deployment, and identity-team involvement. Your application code is unchanged — the `/authorize` request simply returns without ever showing a prompt. Worth pursuing for a large managed desktop estate; not something to attempt during a demo build.

---

## 11. Sign-out and session termination

Three distinct operations, routinely conflated, with very different effects.

### 11.1 Local sign-out

`AppA` discards its tokens. The Okta session is untouched.

```csharp
public async Task SignOutLocalAsync(CancellationToken ct)
{
    // Revoke server-side FIRST — if the process dies after clearing local
    // state, an unrevoked refresh token is left alive in Okta.
    if (_tokens?.RefreshToken is not null)
        await RevokeAsync(_tokens.RefreshToken, "refresh_token", ct);

    _store.Clear();
    _accessTokens.Clear();
    _tokens = null;
    User    = null;

    RaiseStateChanged(AuthenticationChangeReason.SignedOut);
}
```

> ⚠️ **This is almost never what a user means by "Log out".** Because the Okta session survives, relaunching `AppA` signs them straight back in with no prompt. To a user who signed out deliberately — on a shared machine, or before handing the laptop over — that looks exactly like a security failure, and they are not wrong. Use local sign-out for *account switching*, never for the "Log out" menu item.

**Revoking the refresh token is the part that matters.** Clearing local state alone leaves a valid, long-lived credential in Okta that a forensic recovery of the DPAPI blob could still use:

```csharp
private async Task RevokeAsync(string token, string hint, CancellationToken ct)
{
    // RFC 7009. Public client: client_id in the body, no secret.
    using var res = await _http.PostAsync($"{Authority}/v1/revoke",
        new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"]           = token,
            ["token_type_hint"] = hint,
            ["client_id"]       = _options.ClientId,
        }), ct);

    // Per RFC 7009 the endpoint returns 200 even for an already-invalid token.
    // A failure here is a network problem, and must not block sign-out.
    if (!res.IsSuccessStatusCode)
        _log.LogWarning("Refresh token revocation returned {Status}", (int)res.StatusCode);
}
```

### 11.2 Global sign-out (RP-initiated logout)

Ends the **Okta session**, so every application prompts on next launch. This is what "Log out" should do.

```csharp
public async Task SignOutGlobalAsync(CancellationToken ct)
{
    var idToken = _tokens?.IdToken;

    await SignOutLocalAsync(ct);           // revoke + clear first

    if (idToken is null) return;

    // OIDC RP-Initiated Logout 1.0. Must happen in the SYSTEM BROWSER —
    // that is where the session cookie lives (§10.1).
    var url = $"{Authority}/v1/logout" +
              $"?id_token_hint={Uri.EscapeDataString(idToken)}" +
              $"&post_logout_redirect_uri={Uri.EscapeDataString(PostLogoutRedirectUri)}";

    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
}
```

> ⚠️ **The `post_logout_redirect_uri` must be registered as a Sign-out redirect URI in Okta (§6.5), or Okta rejects the request.** Every loopback port in your pool needs its sign-out counterpart registered too.

> ⚠️ **Global sign-out from `AppA` signs the user out of `AppB` as well.** That is the correct and intended meaning of SSO — one session, one sign-out — but it surprises users, and it will be reported as a bug. Say so in the confirmation dialog: *"You will be signed out of all Corp applications."*

### 11.3 Back-channel logout

When an administrator terminates a session in the Okta console, or a user signs out from a *different* device, your APIs' server-side state should be invalidated too. Okta can POST a signed logout token to a registered endpoint per application ([OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)).

Relevant only if your APIs hold server-side session state. If they are stateless — validating a JWT per request, holding nothing — there is nothing to invalidate, and short token lifetimes already bound the exposure. **The stateless design is the reason you can mostly skip this**, which is a good argument for keeping it stateless.

### 11.4 What sign-out cannot do

> ⚠️ **Already-issued access tokens remain valid until they expire.** No sign-out mechanism recalls them — a JWT is verified offline by design, and nothing consults Okta at validation time.
>
> This is the direct consequence of the design's best availability property (§9.4), and the trade is deliberate. The controls that bound it are:
> - **Short access-token lifetimes.** 15 minutes means a 15-minute worst case. This is the primary control, and the reason §5.6 sets it there.
> - **Refresh token revocation.** Cuts off *renewal* immediately, which is what stops a departing employee at the hour boundary rather than the 90-day one.
> - **Introspection**, if a specific high-value endpoint genuinely needs instant revocation — at the cost of an Okta round trip per request, and an availability dependency on Okta. Apply it to one or two endpoints, never globally.
>
> Whoever signs off the security review must understand and accept this. Write it down; do not let it be discovered during an incident.
---

# Part IV — Operate

## 12. Security hardening and threat model

### 12.1 Threat model

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Authorization code intercepted on loopback | PKCE `S256` (§4.1); `state` validation | Negligible |
| T2 | Malicious app registers a competing URI scheme | Loopback instead of custom scheme (§4.3) | Negligible |
| T3 | Credentials phished by a fake in-app login form | System browser only (§4.2); users trained that sign-in is *always* in the browser | Users can still be phished elsewhere; MFA/FastPass mitigates |
| T4 | Refresh token stolen from disk | DPAPI `CurrentUser` (§8.6); rotation with reuse detection (§5.6) | **Malware as the signed-in user reads it.** Bound by rotation detection + DPoP (§12.4) |
| T5 | Access token stolen in transit | TLS 1.2+ everywhere, HSTS, cert pinning optional | Corporate TLS interception is a real exposure (§13.4) |
| T6 | Access token replayed at a different API | Audience validation (§9.2) | None, provided `ValidateAudience` stays on |
| T7 | `ApiB` replays a forwarded `ApiA` token | Patterns 1/2/3 (§7); never Pattern 5 | None if §7.5 is avoided |
| T8 | Service credential leaked from config | `private_key_jwt` with a non-exportable key (§4.4, §6.6) | Key theft requires host compromise |
| T9 | Departing employee retains access | Okta deprovisioning; short token lifetimes; refresh revocation (§11.4) | Up to one access-token lifetime (15 min) |
| T10 | Over-broad scope grant | Least-privilege scope design (§5.4); per-client policies (§6.7) | Requires review discipline |
| T11 | Delegation cycle exhausts Okta rate limits | Depth limiting (§7.7); trace-based cycle detection | Requires the guard to actually be registered |
| T12 | Token contents leaked via logs | Never log tokens (§12.5); structured redaction; log review | Requires review discipline |
| T13 | Okta outage blocks all access | Offline JWT validation; cached JWKS (§9.4) | New sign-ins fail; existing sessions continue |

### 12.2 Non-negotiables

These are the rules that, if broken, make everything else in this document decorative:

1. `ValidateAudience = true`, always, in every environment. (§9.2)
2. `ValidateIssuer = true` with an exact `ValidIssuer`. (§9.2)
3. `ValidAlgorithms` pinned to `RS256`. Never accept `none`; never accept an HMAC algorithm.
4. Never trust `jku`, `x5u`, or `jwk` headers in an inbound token. The key source is **configuration**, never the token itself.
5. `RequireHttpsMetadata = true` in every environment.
6. Never log a token, an authorization code, a refresh token, a device secret, or a client assertion.
7. Never forward a token outside its audience. (§7.5)
8. Never use a service-identity token to serve a user-initiated request. (§7.2)
9. Client-side authorization is UX. Every rule is re-enforced server-side. (§8.13)

### 12.3 Token lifetime policy

| Token | Lifetime | Storage | Revocable? |
|---|---|---|---|
| Authorization code | ~60 s, single use | Memory only | N/A |
| Access token | **15 min** | Memory only, never on disk | ❌ Not until expiry |
| ID token | Matches access token | Memory only | ❌ |
| Refresh token | 90 d, 7 d idle, rotating | DPAPI-encrypted | ✅ `/v1/revoke` |
| Device secret (Appendix A) | Follows the refresh token | DPAPI-encrypted | ✅ `/v1/revoke` |
| Client assertion | 5 min, `jti` replay-guarded | Generated per request | N/A |
| Exchanged (OBO) token | ≤ subject token's expiry | Server memory cache | ❌ |

> ⚠️ **Access tokens never touch disk.** Only the refresh token is persisted. An access token written to disk — a cache file, a crash dump, a debug log — is a bearer credential sitting in the filesystem with no rotation and no revocation.

### 12.4 DPoP — the meaningful upgrade

Every token discussed so far is a **bearer** token: possession is sufficient. Steal it, use it.

**DPoP** ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) sender-constrains tokens to a key pair held by the client. The client generates a key, proves possession on each request with a signed `DPoP` proof JWT, and Okta binds the issued token to that key. A stolen token is then useless without the private key — which never leaves the originating machine. Okta supports DPoP for both the token endpoint and non-Okta resource servers.

**Adopt it when:** the desktop estate is not fully trusted (BYOD, contractors, shared machines), or when T4 is the risk your security review keeps returning to. It is the strongest available mitigation for stolen-token attacks and it directly addresses the honest limit of DPAPI (§8.6).

**Understand the cost:** every client must generate and protect a key pair, sign a fresh proof per request, and handle `use_dpop_nonce` challenges; both APIs must validate proofs, including replay protection. It is a meaningful engineering increment across all four applications.

**Recommendation:** build and ship the bearer-token architecture in this document first. Treat DPoP as a **planned phase two** with a defined trigger — for example, the first time a desktop is confirmed compromised, or when the estate opens to unmanaged devices. Design for it now by keeping token acquisition behind `IAuthenticationService` (§8.3), so adding DPoP touches one class per side rather than every call site.

References: [Configure DPoP](https://developer.okta.com/docs/guides/dpop/nonoktaresourceserver/main/) · [Elevate access token security with DPoP](https://developer.okta.com/blog/2024/09/05/dpop-oauth)

### 12.5 Logging rules

```csharp
// A redacting enricher, so a mistake anywhere in the codebase is caught centrally
// rather than depending on every developer remembering the rule.
public static class LogRedaction
{
    private static readonly Regex Jwt = new(
        @"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        RegexOptions.Compiled);

    public static string Scrub(string message) => Jwt.Replace(message, "[REDACTED-JWT]");
}
```

**Log these** — they are the diagnostic backbone in §14:

- Token acquisition **outcome** (success/failure) with the Okta `error` code, the client ID, and the requested audience and scopes
- The token's `jti`, `sub`/`uid`, and `exp` — identifiers, not the token
- The signing-key `kid` in use, for rotation debugging
- Delegation depth and the `traceparent` on every outbound call
- Every authorization **denial**, with the policy name and the missing scope

**Never log** the token, the authorization code, the `code_verifier`, the refresh token, the device secret, or the client assertion.

> ⚠️ **The most common leak is an unhandled exception.** A failed HTTP call whose request URI or headers are serialised into an exception message and then logged at `Error` will put a token into your log aggregator, where it is indexed, replicated, and retained for a year. The `OnAuthenticationFailed` handler in §9.2 logs the exception *type and message* rather than the context for exactly this reason.

---

## 13. Deployment on IIS

### 13.1 Hosting model

Use **in-process** hosting (the ASP.NET Core Module v2 default). It avoids a loopback proxy hop and keeps token validation in the same process as the request.

```xml
<PropertyGroup>
  <AspNetCoreHostingModel>inprocess</AspNetCoreHostingModel>
  <TargetFramework>net8.0</TargetFramework>
</PropertyGroup>
```

### 13.2 Application pool

| Setting | Value | Why |
|---|---|---|
| .NET CLR version | **No Managed Code** | The runtime is in the app, not IIS |
| Identity | A dedicated `ApplicationPoolIdentity` or gMSA | Never `NetworkService`, never a shared account |
| **Load User Profile** | **`True`** | **Required** for certificate private-key access and DPAPI |
| Start Mode | **AlwaysRunning** | Avoids a cold start paying the Okta metadata fetch (§9.4) |
| Idle Time-out | **0** | Prevents recycling that discards the JWKS cache |
| Regular Time Interval | 0, with a scheduled off-hours recycle | Avoids mid-day cache loss |

> ⚠️ **`Load User Profile = False` produces a bewildering failure.** The application starts, serves requests, validates inbound tokens perfectly — and every *outbound* call fails, because the cryptographic provider cannot open the certificate's private key from the pool identity's profile. The exception is a generic `CryptographicException: Keyset does not exist`, with nothing pointing at IIS configuration. Set it to `True` first, and check it first when outbound auth fails but inbound works.

### 13.3 Certificate private-key permissions

Installing the certificate is not sufficient; the pool identity needs read access to the private key.

```powershell
$thumb   = "A1B2C3D4E5F6..."
$appPool = "IIS AppPool\ApiA"

$cert = Get-Item "Cert:\LocalMachine\My\$thumb"
$keyFile = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$keyPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyFile"

$acl  = Get-Acl $keyPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $appPool, "Read", "Allow")
$acl.AddAccessRule($rule)
Set-Acl -Path $keyPath -AclObject $acl
```

For CNG keys (which `New-SelfSignedCertificate` produces by default on modern Windows) the path is under `%ProgramData%\Microsoft\Crypto\Keys` instead. The GUI equivalent — `certlm.msc` → the certificate → **All Tasks → Manage Private Keys** → add `IIS AppPool\ApiA` with Read — handles both and is less error-prone. Automate it in the deployment script either way, and **verify it as a post-deploy health check**, because it is silently lost on a certificate reinstall.

### 13.4 Network egress and TLS interception

Both APIs must reach Okta outbound over HTTPS:

| Destination | Purpose | Frequency |
|---|---|---|
| `https://{yourOktaDomain}/oauth2/*/.well-known/*` | Metadata discovery | Startup, then every 6–12 h |
| `https://{yourOktaDomain}/oauth2/*/v1/keys` | JWKS | With metadata |
| `https://{yourOktaDomain}/oauth2/*/v1/token` | Token exchange / client credentials | Per uncached delegated call |

> ⚠️ **Corporate TLS-inspecting proxies are the number one cause of "it works on my machine, fails on the server."** The proxy re-signs Okta's certificate with an internal CA. If that CA is not in the server's `LocalMachine\Root` store, the metadata fetch fails with `AuthenticationException: The remote certificate is invalid`, and the API returns 401 for *every* request with no obvious link to the proxy. Verify from the server itself before blaming the code:
>
> ```powershell
> Invoke-WebRequest "https://{yourOktaDomain}/oauth2/{authServerId}/.well-known/openid-configuration" |
>   Select-Object -ExpandProperty Content
> ```
>
> If that fails, no amount of application configuration will help. Fix the trust chain, or exempt the Okta domain from inspection.

If an explicit proxy is required:

```csharp
builder.Services.AddHttpClient("okta").ConfigurePrimaryHttpMessageHandler(() =>
    new HttpClientHandler
    {
        Proxy = new WebProxy("http://proxy.contoso.internal:8080")
        {
            Credentials = CredentialCache.DefaultNetworkCredentials
        },
        UseProxy = true,
    });
```

### 13.5 Clock synchronisation

Token validation is time-based. `exp`, `nbf`, and `iat` are all compared against the local clock, and §9.2 deliberately narrows `ClockSkew` from the 5-minute default to 30 seconds.

```powershell
w32tm /query /status
w32tm /resync
```

> ⚠️ **A drifting clock produces the most confusing failure in this whole document.** An API host 90 seconds fast rejects freshly-minted tokens as *not yet valid* (`IDX10222`); one 90 seconds slow rejects valid tokens as expired (`IDX10223`). Both look like an Okta problem, both are intermittent, and both resolve "on their own" whenever the clock happens to drift back. Monitor clock offset on every API host and **alert on it** — this is worth a dedicated check.

### 13.6 Request header limits

JWTs with a `groups` claim can exceed default header limits, especially in a large tenant.

```xml
<!-- web.config -->
<system.webServer>
  <security>
    <requestFiltering>
      <requestLimits maxAllowedContentLength="30000000">
        <headerLimits>
          <add header="Authorization" sizeLimit="32768" />
        </headerLimits>
      </requestLimits>
    </requestFiltering>
  </security>
</system.webServer>
```

`http.sys` also caps header sizes below IIS, and its limits are registry-level:

```
HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters
    MaxFieldLength   (DWORD)  default 16384
    MaxRequestBytes  (DWORD)  default 16384
```

> ⚠️ **The right fix is almost always to shrink the token, not to raise the limit.** A `groups` claim without the `Starts with App-` filter (§5.5) is the usual cause. Raising limits treats the symptom, leaves you carrying kilobytes of irrelevant group names on every request, and hits the next limit — a load balancer, an API gateway, a WAF — somewhere less diagnosable.

### 13.7 Desktop client deployment

- **Ship `appsettings.{Environment}.json`** with the installer, not baked into the executable — the same binary should be promotable across environments.
- **No elevation required.** Loopback redirects need no URL ACL and no registry writes (§4.3, §8.5). If your installer asks for admin rights, something has crept into the design.
- **Whitelist the loopback ports** if a host firewall blocks local binds on the SOE image.
- **The default browser must be set.** A machine with no default browser association cannot sign in; §8.5 detects and reports this rather than failing opaquely.
- **Roaming profiles:** DPAPI `CurrentUser` blobs follow the roaming profile, so tokens roam with the user across machines. That is usually desirable. If your security posture forbids it, add machine entropy to the DPAPI call and accept a re-authentication on each new machine.

---

## 14. Observability and troubleshooting

### 14.1 The Okta System Log is your first stop

**Reports → System Log**, or the `/api/v1/logs` API. For any authentication problem, look here **before** reading application logs — Okta records the policy decision and its reason, which your application never sees.

| Event type | Meaning |
|---|---|
| `user.authentication.auth_via_mfa` | The user authenticated |
| `user.session.start` | An Okta session was created — the SSO cookie (§10.1) |
| `app.oauth2.as.authorize` | An `/authorize` request; shows the client, scopes, and outcome |
| `app.oauth2.as.token.grant` | A token was issued; shows the grant type and scopes |
| `app.oauth2.as.token.grant.refresh_token` | A refresh — watch for rotation-reuse failures |
| `app.oauth2.as.consent.grant` | Consent recorded |
| `policy.evaluate_sign_on` | Which sign-on policy rule matched, and why |
| `system.org.rate_limit.warning` | **Approaching a rate limit** — alert on this (§7.7) |

Filter by `target.id` for a specific app integration to see one application's traffic in isolation.

### 14.2 Failure decision tree

```
Sign-in fails
├─ Does Token Preview work in the Admin Console? (§6.8)
│  ├─ NO  → The problem is Okta configuration, not code.
│  │        Check: app assignment · access policy rule order ·
│  │               scopes defined on the AS · user's group membership
│  └─ YES → The problem is in the client or on the network.
│           Check: redirect URI exact match (incl. port) ·
│                  client_id/authority environment mismatch ·
│                  the port bound matches a registered URI
│
API returns 401 with a token the client believes is valid
├─ Decode the token at jwt.io (a NON-PRODUCTION token only)
│  ├─ aud ≠ the API's audience     → §7.5 anti-pattern, or wrong resource requested
│  ├─ iss ≠ configured issuer      → Org AS vs Custom AS mix-up (§5.1)
│  ├─ exp in the past              → clock skew (§13.5) or a stale cache
│  └─ all correct                  → JWKS fetch is failing: TLS interception (§13.4)
│                                     or blocked egress
│
API returns 403
└─ Token is valid; authorization failed.
   Check: 'scp' contains the required scope · 'groups' present and filtered ·
          the policy name in the denial log line (§12.5)
```

> ⚠️ **Never paste a production token into jwt.io or any online decoder.** It is a live credential, and you are sending it to a third party. Decode locally: `dotnet tool install -g dotnet-jwt`, or a five-line script over `System.IdentityModel.Tokens.Jwt`. Make this a written team rule — it is one of the easiest ways to leak a working credential.

### 14.3 Error reference

| Error | Where | Cause | Fix |
|---|---|---|---|
| `The 'redirect_uri' parameter must be an absolute URI that is whitelisted in the client app settings` | `/authorize` | Bound port not registered, or `localhost` vs `127.0.0.1` | Register every port in the pool (§6.5) |
| `invalid_client` | `/token` | Wrong `client_id`; or assertion `aud` is not the token endpoint URL; or the public key is not registered | §7.1 assertion factory; §6.6 key registration |
| `invalid_grant` | `/token` | Code reused/expired; PKCE verifier mismatch; `redirect_uri` differs from the one at `/authorize` | Never retry a code; ensure the same port is used for both legs |
| `invalid_scope` | `/token` | Scope not defined on this AS, or not granted by policy | §6.3, §6.7 |
| `access_denied` | `/authorize` | **User not assigned to the app**, or no policy rule matched | Check assignments *and* policy (§3.5) |
| `unsupported_grant_type` | `/token` | Grant not enabled on the app integration | Enable Token Exchange / Client Credentials (§6.5) |
| `IDX10214: Audience validation failed` | API | Token's `aud` ≠ configured audience | The token is for a different API — §7 |
| `IDX10205: Issuer validation failed` | API | Org AS token at a Custom AS-configured API, or wrong `authServerId` | §5.1 |
| `IDX10223: Lifetime validation failed. The token is expired` | API | Genuine expiry, or a slow clock | §13.5 |
| `IDX10222: Lifetime validation failed. The token is not yet valid` | API | Clock ahead of Okta | §13.5 |
| `IDX10501: Signature validation failed. Unable to match key: kid` | API | JWKS cache predates a key rotation | Verify egress; `ConfigurationManager` self-heals within its refresh interval (§9.4) |
| `IDX10500: Signature validation failed. No security keys were provided` | API | Metadata fetch failed entirely | §13.4 TLS interception / egress |
| `CryptographicException: Keyset does not exist` | API outbound | App pool cannot read the private key | §13.2 Load User Profile, §13.3 ACL |
| `HTTP 431` / truncated `Authorization` | IIS | Token exceeds header limits | Filter the `groups` claim (§5.5), then §13.6 |
| Browser flashes, then "sign-in failed" | Client | Loopback bind blocked, or the browser closed early | §8.5; check host firewall |
| `AppB` prompts every day | Client | Okta session cookie not persisted across browser restarts | §10.1 — the single most common SSO complaint |

### 14.4 Health checks

```csharp
builder.Services.AddHealthChecks()
    // Okta reachability — DEGRADED, not unhealthy: cached keys mean the API
    // still validates existing tokens during an Okta outage (§9.4). Failing
    // the health check here would take the API out of the load balancer for
    // an outage it can actually survive.
    .AddUrlGroup(new Uri($"{okta.Issuer}/.well-known/openid-configuration"),
                 name: "okta-metadata",
                 failureStatus: HealthStatus.Degraded)

    // The signing certificate — UNHEALTHY. Without it, no outbound delegated
    // call can be made at all.
    .AddCheck<SigningCertificateHealthCheck>("okta-client-certificate")

    // Clock drift against Okta's Date header (§13.5).
    .AddCheck<ClockSkewHealthCheck>("clock-skew");
```

`SigningCertificateHealthCheck` should verify the certificate is present, the private key is **readable by the current identity** (catching §13.3 regressions), and that it expires more than 30 days out — so rotation is a planned change rather than an outage.

### 14.5 Metrics worth alerting on

| Metric | Alert when | Indicates |
|---|---|---|
| `okta.token.exchange.failures` | > 1% of attempts | Policy/trust misconfiguration (§5.7) |
| `okta.token.exchange.latency.p99` | > 2 s | Okta degradation or a cache that is not working |
| `okta.delegated_token.cache.hit_ratio` | < 80% | Cache keying is wrong — check §7.1 |
| `auth.401.rate` | Step change | Key rotation, clock drift, or a bad deploy |
| `auth.403.rate` | Step change | Scope or group configuration change |
| `okta.rate_limit.warnings` | **Any** | Possible delegation cycle (§7.7) — page someone |
| `clock.skew.seconds` | > 15 s | §13.5 |
| `certificate.days_to_expiry` | < 30 | Rotation due (§6.6) |

---

## 15. Testing strategy

### 15.1 What to test, and at which level

| Level | Target | Approach |
|---|---|---|
| Unit | Scope/claims helpers, assertion factory, cache keying | Plain xUnit, no network |
| Unit | Token **validation**, especially the negative cases | `WebApplicationFactory` + a locally-generated signing key |
| Architecture | The non-negotiables in §12.2 | Reflection/analyzer tests that fail the build |
| Integration | The real Okta flows | A dedicated Okta test tenant |
| Manual | Browser flow, SSO between apps, sign-out | Scripted checklist (§16) |

### 15.2 Guard the non-negotiables in CI

The rules in §12.2 are worth exactly as much as your ability to stop someone quietly relaxing one at 5pm on a Friday. Make them build failures:

```csharp
[Fact]
public void JwtBearer_must_validate_audience_and_issuer()
{
    using var factory = new WebApplicationFactory<Program>();
    var options = factory.Services
        .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
        .Get(JwtBearerDefaults.AuthenticationScheme);

    options.TokenValidationParameters.ValidateAudience.Should().BeTrue(
        "disabling audience validation makes every token in the Okta org valid here (§9.2)");
    options.TokenValidationParameters.ValidateIssuer.Should().BeTrue();
    options.TokenValidationParameters.ValidateIssuerSigningKey.Should().BeTrue();
    options.TokenValidationParameters.ValidAlgorithms
        .Should().BeEquivalentTo(new[] { SecurityAlgorithms.RsaSha256 });
    options.TokenValidationParameters.ClockSkew
        .Should().BeLessThanOrEqualTo(TimeSpan.FromSeconds(60));
    options.RequireHttpsMetadata.Should().BeTrue();
    options.MapInboundClaims.Should().BeFalse();
}

[Fact]
public void No_handler_forwards_the_inbound_authorization_header()
{
    // The §7.5 anti-pattern, caught structurally rather than by review.
    var offenders = typeof(Program).Assembly.GetTypes()
        .Where(t => typeof(DelegatingHandler).IsAssignableFrom(t))
        .Where(ForwardsInboundAuthorizationHeader);

    offenders.Should().BeEmpty(
        "forwarding a token outside its audience is the confused-deputy defect (§7.5)");
}
```

### 15.3 Negative tests are the valuable ones

A test that a valid token is accepted proves very little — that path is exercised by every manual run. The tests that earn their keep assert what must be **rejected**:

```csharp
public sealed class TokenValidationTests : IClassFixture<TestKeyFixture>
{
    [Fact] public async Task Rejects_token_for_a_different_audience()   // → 401
    [Fact] public async Task Rejects_an_id_token()                      // → 401  (§3.2)
    [Fact] public async Task Rejects_a_token_from_a_different_issuer()  // → 401
    [Fact] public async Task Rejects_an_expired_token()                 // → 401
    [Fact] public async Task Rejects_a_tampered_payload()               // → 401
    [Fact] public async Task Rejects_alg_none()                         // → 401
    [Fact] public async Task Rejects_an_HMAC_signed_token()             // → 401  (alg confusion)
    [Fact] public async Task Rejects_a_valid_token_missing_the_scope()  // → 403
    [Fact] public async Task Rejects_a_service_token_on_a_user_endpoint()// → 403 (§7.2)
    [Fact] public async Task Refuses_to_delegate_past_max_depth()       // → 508 (§7.7)
}
```

Substitute a local signing key so tests need no network and no Okta tenant:

```csharp
public sealed class TestKeyFixture
{
    public RsaSecurityKey Key { get; } = new(RSA.Create(2048)) { KeyId = "test-key-1" };

    public string CreateToken(string audience = "api://apia",
                              string issuer   = "https://test.okta.local/oauth2/default",
                              string[]? scopes = null,
                              DateTime? expires = null,
                              string alg = SecurityAlgorithms.RsaSha256)
    { /* ... */ }
}

// In the test host, replace only the KEY SOURCE. Every other validation
// parameter must come from production configuration, or the tests validate
// a configuration that is never deployed.
builder.ConfigureTestServices(s =>
    s.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o =>
    {
        o.TokenValidationParameters.IssuerSigningKey = fixture.Key;
        o.TokenValidationParameters.ValidIssuer      = "https://test.okta.local/oauth2/default";
        o.ConfigurationManager = null;   // no metadata fetch
        o.RequireHttpsMetadata = false;  // ONLY acceptable because there is no metadata endpoint
    }));
```

> ⚠️ **Override the key source and nothing else.** Every test host that relaxes `ValidateAudience` or `ValidAlgorithms` "to make the test pass" is testing a configuration you will never deploy, and it makes the §15.2 guards worthless.

### 15.4 Integration tests against a real Okta tenant

Some things only a real tenant can prove: policy evaluation, scope grants, the trusted-server relationship, and token exchange.

- Use a **dedicated test tenant**, never production.
- Use a **service account** with client credentials for CI. Never automate a browser flow with a real user's password — that reintroduces exactly the credential handling §4.5 exists to eliminate.
- Keep integration tests in a separate, non-gating CI job. They depend on an external service and will occasionally fail for reasons unrelated to your change.
- **Assert on token *contents*, not just on HTTP 200.** The whole point is that `aud`, `sub`, and `scp` are correct:

```csharp
[Fact]
public async Task Obo_exchange_preserves_user_and_retargets_audience()
{
    var userToken = await _fixture.GetUserTokenAsync("api://apia", "apia.read");
    var exchanged = await _exchange.ExchangeAsync(userToken, "api://apib", "apib.read", default);

    var jwt = new JsonWebTokenHandler().ReadJsonWebToken(exchanged);

    jwt.Audiences.Should().Contain("api://apib");
    jwt.Subject.Should().Be(new JsonWebTokenHandler()
        .ReadJsonWebToken(userToken).Subject, "the user's identity must survive delegation");
    jwt.GetClaim("cid").Value.Should().Be(_fixture.ApiAServiceClientId,
        "the acting service must be recorded for audit");
}
```

### 15.5 Manual test matrix

| # | Scenario | Expected |
|---|---|---|
| 1 | First launch of `AppA`, no session | Browser opens, credentials + MFA, app loads |
| 2 | Relaunch `AppA` within refresh lifetime | Silent, no browser |
| 3 | Launch `AppB` after 1, same day | Browser flashes, **no prompt** (§10.1) |
| 4 | Launch `AppB` after closing all browser windows | Still no prompt — verifies persistent cookie (§10.1) |
| 5 | Leave `AppA` idle past access-token expiry, then act | Silent refresh, request succeeds |
| 6 | Revoke the refresh token in Okta, then act | Clean re-authentication prompt, no crash |
| 7 | Trigger an `ApiA → ApiB` call | Succeeds; `ApiB` log shows the correct `sub` and `cid` |
| 8 | Deactivate the user in Okta mid-session | Fails within one access-token lifetime (§11.4) |
| 9 | Global sign-out from `AppA`, then launch `AppB` | `AppB` prompts |
| 10 | Disconnect the network, then act in `AppA` | Clear offline message, no hang, no token loss |
| 11 | Sleep the laptop overnight, resume, act | Re-auth prompt or silent restore — never a wall of 401s (§8.8) |
| 12 | Run `AppA` twice simultaneously | Second instance binds the next port and signs in (§8.5) |

Scenarios **4**, **11**, and **12** are the ones teams skip and users find first.

---

## 16. Go-live checklist

**Okta configuration**
- [ ] API Access Management confirmed available in the production org (§5.1)
- [ ] Variant A vs B decided and recorded (§5.2); if A, the multi-audience EA feature is enabled in production
- [ ] Custom Authorization Server(s) created; metadata URL resolves (§6.2)
- [ ] Scopes defined; no `*.admin` or `full_access` scope exists (§5.4)
- [ ] `groups` claim configured **with a filter** (§5.5)
- [ ] Access policies scoped to specific clients, rules ordered, catch-all deny last (§6.7)
- [ ] Access token lifetime ≤ 15 min; refresh rotation enabled with a 30 s grace (§5.6)
- [ ] All loopback redirect URIs registered — sign-in **and** sign-out, every port (§6.5)
- [ ] App assignments granted to the correct groups (§3.5)
- [ ] Global Session Policy: **persistent cookie across browser restarts enabled** (§10.1)
- [ ] Token Preview verified for every client × grant-type combination (§6.8)
- [ ] Configuration captured in Terraform or a documented runbook (§6.9)

**Security**
- [ ] §7 pattern decided, recorded, and the spike in §7.6 actually run
- [ ] No `ValidateAudience = false` anywhere, guarded by a test (§15.2)
- [ ] `RequireHttpsMetadata = true` in all environments (§9.2)
- [ ] `ValidAlgorithms` pinned to RS256 (§9.2)
- [ ] `FallbackPolicy` set — deny by default (§9.3)
- [ ] Delegation depth guard registered on every outbound client (§7.7)
- [ ] Log redaction in place; a sample log reviewed for tokens (§12.5)
- [ ] Client-side gates each have a matching server-side check (§8.13)
- [ ] Threat model reviewed and residual risks accepted in writing (§12.1)
- [ ] §11.4 — the "access tokens survive sign-out" trade — signed off explicitly

**Infrastructure**
- [ ] App pool: **Load User Profile = True**, AlwaysRunning, idle timeout 0 (§13.2)
- [ ] Certificate installed, private-key ACL granted, verified post-deploy (§13.3)
- [ ] Egress to Okta confirmed **from the servers themselves** (§13.4)
- [ ] TLS-inspection CA trusted, or the Okta domain exempted (§13.4)
- [ ] NTP verified on every API host; clock-skew alert configured (§13.5)
- [ ] Header limits sized for real production tokens (§13.6)
- [ ] Certificate expiry monitored, 30-day alert (§14.4)
- [ ] Second signing key registered ahead of the first rotation (§6.6)

**Operations**
- [ ] Health checks deployed; Okta reachability is **Degraded**, not Unhealthy (§14.4)
- [ ] Alert on `system.org.rate_limit.warning` (§7.7, §14.1)
- [ ] Distributed tracing propagates `traceparent` across all four applications
- [ ] Runbook covers: certificate rotation, Okta outage, delegation cycle, mass 401s
- [ ] Manual test matrix executed in the production tenant, including cases 4, 11, 12 (§15.5)
- [ ] Support team briefed on the two expected behaviours in §10.2
---

# Appendices

## Appendix A — Okta Native SSO

The optional upgrade referenced in §10.3: SSO between `AppA` and `AppB` with **no browser at all** for the second app.

### A.1 How it works

`AppA` signs in once through the browser and additionally requests the `device_sso` scope. Okta returns a **device secret** alongside the usual tokens. `AppB` then presents `AppA`'s ID token plus that device secret to the token endpoint via RFC 8693 token exchange, and receives its own independent set of tokens.

```
AppA ── browser, PKCE, scope=openid offline_access device_sso ──► Okta
     ◄── access_token + id_token + refresh_token + DEVICE_SECRET

        [ device secret stored in a location both apps can read,
          DPAPI-encrypted — see the warning in A.4 ]

AppB ── POST /v1/token ──────────────────────────────────────────► Okta
        grant_type       = urn:ietf:params:oauth:grant-type:token-exchange
        subject_token    = <AppA's id_token>
        subject_token_type = urn:ietf:params:oauth:token-type:id_token
        actor_token      = <device_secret>
        actor_token_type = urn:x-oath:params:oauth:token-type:device-secret
        scope            = openid offline_access
        audience         = <authorization server URI>
        client_id        = <AppB's client_id>
     ◄── AppB's OWN access_token + id_token + refresh_token
         (independent refresh lifecycle)
```

### A.2 Prerequisites

- **Native SSO enabled** on the org.
- Both app integrations have the **Token Exchange** grant type enabled (Admin Console → the app → *General* → *Grant type* → **Advanced** → **Token Exchange**).
- The authorization server offers the `device_sso`, `openid`, and `offline_access` scopes.
- Both apps are governed by **compatible assurance policies**.

> ⚠️ **Okta documents an error when the two apps have mismatched assurance levels** — one on a low-assurance policy and the other on high. Give both apps the same assurance policy, or Native SSO fails between them in a way that is hard to attribute.

### A.3 Device secret lifecycle

The device secret takes the lifetime of the first refresh token it was minted with, inheriting the same idle and maximum times from the governing access policy.

| Operation | Endpoint |
|---|---|
| Validate; retrieve the session ID (`sid`) | `POST /v1/introspect` with `token_type_hint=device_secret` |
| Revoke — signs out **every** participating app | `POST /v1/revoke` with the device secret |
| Sign out | `POST /v1/logout` with `id_token_hint` **and** `device_secret` |

Revoking the device secret is genuine **Single Logout** across the native estate — the strongest logout story available to a desktop application, and the main reason to adopt Native SSO beyond removing the browser flash.

### A.4 Trade-offs

**Gains:** no browser for the second app; true Single Logout; works when the browser is locked down or cookies are cleared.

**Costs:**
- A **new high-value secret** to store, protect, and revoke.
- An org feature dependency and a coupled assurance policy across both apps.
- Both apps must be updated together to adopt it.

> ⚠️ **The device secret is shared state between two applications, and that reintroduces the risk §4.7 rejected.** Storing it where both apps can read it means compromising the weaker application yields SSO for both. Mitigate by keeping it DPAPI-encrypted under `CurrentUser` (§8.6), storing it under a location only these apps use, and revoking it aggressively on sign-out. If the two applications have genuinely different trust levels, Native SSO is the wrong choice — stay with browser-session SSO, where each app holds only its own tokens.

**Verdict:** adopt when the browser round trip is a *business* problem — a kiosk, a shop-floor terminal, a locked-down environment. Do not adopt merely because it is tidier.

References: [Configure SSO for Native apps](https://developer.okta.com/docs/guides/configure-native-sso/main/) · [Native SSO: Desktop and Mobile Apps Single Sign-On](https://developer.okta.com/blog/2021/11/12/native-sso)

---

## Appendix B — Configuration reference sheet

Fill this in as you work through §6. Every other section refers back to it.

### B.1 Tenant

| Item | Value |
|---|---|
| Okta domain | `___________________.okta.com` |
| Custom domain (if any) | `___________________` |
| Org type | ☐ Integrator Free ☐ Production |
| API Access Management confirmed | ☐ Yes ☐ No |
| Topology | ☐ Variant A (one AS, two audiences) ☐ **Variant B (one AS per API)** |
| Multi-audience EA enabled *(Variant A only)* | ☐ Yes ☐ N/A |
| Token Exchange available | ☐ Yes ☐ No → §7 falls back to Pattern 3 |
| Native SSO enabled | ☐ Yes ☐ No (Appendix A) |

### B.2 Authorization servers

| | `apia-as` | `apib-as` |
|---|---|---|
| Authorization Server ID | `aus________________` | `aus________________` |
| Issuer | `https://____/oauth2/____` | `https://____/oauth2/____` |
| Audience | `api://apia` | `api://apib` |
| Metadata URL verified | ☐ | ☐ |
| Trusted servers configured | `______________` | `______________` |
| Access token lifetime | ______ min | ______ min |
| Refresh lifetime / idle | ____ d / ____ d | ____ d / ____ d |

### B.3 App integrations

| | `AppA` | `AppB` | `ApiA` service | `ApiB` service |
|---|---|---|---|---|
| Client ID | `0oa_________` | `0oa_________` | `0oa_________` | `0oa_________` |
| App type | Native | Native | API Services | API Services |
| Client auth | `none` | `none` | `private_key_jwt` | `private_key_jwt` |
| Grants | code, refresh | code, refresh | client_creds (+exch) | client_creds (+exch) |
| Redirect URIs | `127.0.0.1:8765/8766/8767` | ☐ registered | — | — |
| Sign-out URIs | ☐ registered | ☐ registered | — | — |
| Cert thumbprint | — | — | `____________` | `____________` |
| Assigned groups | `______` | `______` | — | — |

### B.4 Scopes

| Scope | Defined on | Granted to |
|---|---|---|
| `apia.read` | `apia-as` | AppA, ApiB service |
| `apia.write` | `apia-as` | AppA |
| `apib.read` | `apib-as` | AppB, ApiA service |
| `apib.write` | `apib-as` | AppB |

### B.5 Decisions to record

| Decision | Choice | Rationale | Date |
|---|---|---|---|
| Topology (§5.2) | | | |
| §7 delegation pattern | | | |
| Cross-app SSO (§10) | | | |
| DPoP now or phase two (§12.4) | | | |
| §11.4 residual risk accepted by | | | |

---

## Appendix C — Raw HTTP transcripts

Read these once. Everything the libraries do is visible here, and when something fails it is these messages you will be comparing against.

### C.1 Authorization request

```http
GET /oauth2/aus1a2b3c4d5e6f7g8h9/v1/authorize
      ?client_id=0oa1a2b3c4d5e6f7g8h9
      &response_type=code
      &scope=openid%20profile%20email%20offline_access%20apia.read%20apia.write
      &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback
      &state=8f14e45fceea167a5a36dedd4bea2543
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
      &nonce=7d793037a0760186574b0282f2f435e7 HTTP/1.1
Host: dev-12345678.okta.com
```

| Parameter | Purpose |
|---|---|
| `state` | CSRF protection. **Must** be verified on the response. |
| `nonce` | Replays of the ID token. Verified inside the ID token. |
| `code_challenge` | PKCE (§4.1) |
| `redirect_uri` | Must match a registered URI **exactly**, port included |

### C.2 Redirect back

```http
HTTP/1.1 302 Found
Location: http://127.0.0.1:8765/callback
            ?code=P59WVl4gVN0jJqZ...
            &state=8f14e45fceea167a5a36dedd4bea2543
```

Verify `state` matches **before** doing anything else with `code`.

### C.3 Token request (public client — no secret, PKCE verifier instead)

```http
POST /oauth2/aus1a2b3c4d5e6f7g8h9/v1/token HTTP/1.1
Host: dev-12345678.okta.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=P59WVl4gVN0jJqZ...
&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback
&client_id=0oa1a2b3c4d5e6f7g8h9
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token_type":    "Bearer",
  "expires_in":    900,
  "access_token":  "eyJraWQiOiJ...",
  "scope":         "openid profile email offline_access apia.read apia.write",
  "refresh_token": "0IuHFyfBS...",
  "id_token":      "eyJraWQiOiJ..."
}
```

> ⚠️ **`redirect_uri` is required here even though no redirect occurs.** It must be byte-identical to the one sent to `/authorize`, and this is a common source of `invalid_grant`.

### C.4 Refresh with rotation

```http
POST /oauth2/aus1a2b3c4d5e6f7g8h9/v1/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=0IuHFyfBS...
&client_id=0oa1a2b3c4d5e6f7g8h9
&scope=openid%20profile%20email%20offline_access%20apia.read
```

```http
{
  "access_token":  "eyJraWQiOiJ...",
  "refresh_token": "kL9mNpQrS...",   ← NEW. Persist immediately (§8.8).
  "expires_in":    900
}
```

### C.5 On-Behalf-Of token exchange (§7.1)

```http
POST /oauth2/aus9z8y7x6w5v4u3t2s1/v1/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&subject_token=eyJraWQiOiJ...
&audience=api%3A%2F%2Fapib
&scope=apib.read
&client_id=0oa9z8y7x6w5v4u3t2s1
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIs...
```

The decoded `client_assertion` — note `aud` is the token endpoint itself:

```json
{
  "iss": "0oa9z8y7x6w5v4u3t2s1",
  "sub": "0oa9z8y7x6w5v4u3t2s1",
  "aud": "https://dev-12345678.okta.com/oauth2/aus9z8y7x6w5v4u3t2s1/v1/token",
  "jti": "3f2504e04f8911d39a0c0305e82c3301",
  "iat": 1735689600,
  "exp": 1735689900
}
```

### C.6 Client credentials (§7.2)

```http
POST /oauth2/aus9z8y7x6w5v4u3t2s1/v1/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=apib.read
&client_id=0oa9z8y7x6w5v4u3t2s1
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIs...
```

The resulting token has **no `sub`** and **no `uid`** — that absence is how `ApiB` recognises a service call (§9.3).

### C.7 Revocation and logout

```http
POST /oauth2/aus1a2b3c4d5e6f7g8h9/v1/revoke HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=0IuHFyfBS...&token_type_hint=refresh_token&client_id=0oa1a2b3c4d5e6f7g8h9
```

```http
GET /oauth2/aus1a2b3c4d5e6f7g8h9/v1/logout
      ?id_token_hint=eyJraWQiOiJ...
      &post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fsignout-callback HTTP/1.1
```

---

---

## Appendix D — Okta response reference

Every response shape you will encounter, annotated. Where a claim is Okta-specific rather than standard, it is marked **[Okta]**.

> ⚠️ **Never depend on claims Okta does not guarantee.** Okta may add claims to any response. Your code must ignore unknown fields, never assume ordering, and never break because a new claim appeared. Conversely, never assume an *optional* claim is present — `groups` only appears if you configured it (§5.5), and `email` only if the `email` scope was granted.

### D.1 Discovery document

`GET https://{yourOktaDomain}/oauth2/{authServerId}/.well-known/openid-configuration`

This is the contract between Okta and your applications. Everything else is derived from it — never hard-code the endpoint URLs when you can read them from here.

```json
{
  "issuer": "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
  "authorization_endpoint": ".../v1/authorize",
  "token_endpoint":         ".../v1/token",
  "userinfo_endpoint":      ".../v1/userinfo",
  "registration_endpoint":  ".../v1/clients",
  "jwks_uri":               ".../v1/keys",
  "introspection_endpoint": ".../v1/introspect",
  "revocation_endpoint":    ".../v1/revoke",
  "end_session_endpoint":   ".../v1/logout",
  "response_types_supported": ["code", "token", "id_token", "code id_token", "..."],
  "grant_types_supported": [
    "authorization_code", "implicit", "refresh_token",
    "password", "client_credentials",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "scopes_supported": ["openid", "profile", "email", "offline_access", "apia.read", "..."],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic", "client_secret_post", "client_secret_jwt",
    "private_key_jwt", "none"
  ],
  "code_challenge_methods_supported": ["S256"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "claims_supported": ["iss", "ver", "sub", "aud", "iat", "exp", "..."]
}
```

**Use it as a diagnostic.** Three checks settle most configuration disputes in seconds:

| Check | Meaning if it fails |
|---|---|
| `issuer` contains `/oauth2/{authServerId}` | You are on the **Org AS**, not a Custom AS (§5.1) |
| `grant_types_supported` includes `token-exchange` | §7 Pattern 1 is unavailable — fall back to Pattern 3 |
| `code_challenge_methods_supported` includes `S256` | PKCE unavailable — stop, something is very wrong |

> ⚠️ **`grant_types_supported` advertises what the *server* can do, not what your *app integration* is allowed to do.** `password` appears in that list on every Okta org. That is not permission to use it (§4.5) — per-client grants are configured on the app integration, and the ROPC grant should never be enabled on yours.

### D.2 Authorization response

**Success** — a 302 to your loopback listener:

```
http://127.0.0.1:8765/callback
  ?code=P59WVl4gVN0jJqZ...
  &state=8f14e45fceea167a5a36dedd4bea2543
```

**Failure** — also a 302, with the error in the query string:

```
http://127.0.0.1:8765/callback
  ?error=access_denied
  &error_description=User+is+not+assigned+to+the+client+application
  &state=8f14e45fceea167a5a36dedd4bea2543
```

> ⚠️ **Validate `state` on the error path too.** It is easy to write a handler that checks `state` only when `code` is present, then logs or displays an attacker-supplied `error_description` from an unsolicited request. Check `state` first, always, before reading any other parameter.

### D.3 Token response

```json
{
  "token_type":    "Bearer",
  "expires_in":    900,
  "access_token":  "eyJraWQiOiJ...",
  "scope":         "openid profile email offline_access apia.read",
  "refresh_token": "0IuHFyfBS...",
  "id_token":      "eyJraWQiOiJ..."
}
```

| Field | Present when | What to do with it |
|---|---|---|
| `token_type` | Always | Always `Bearer` (or `DPoP` under §12.4). Use it verbatim in the header. |
| `expires_in` | Always | **Seconds**, not a timestamp. Compute `exp` locally; this is the only expiry the client should use (§3.2). |
| `access_token` | Always | Send to the API. Never decode. Never persist (§12.3). |
| `scope` | Always | What was **actually granted** — may be *narrower* than requested. |
| `refresh_token` | `offline_access` granted | Persist encrypted. Rotates on every use (§8.8). |
| `id_token` | `openid` granted | The user's identity for the UI. Validate, then read claims. |
| `device_secret` | `device_sso` granted | Native SSO only (Appendix A). |

> ⚠️ **`scope` in the response is the granted set, and it can be smaller than what you asked for.** Okta narrows it silently when policy does not permit a requested scope — no error, just a shorter list. A client that assumes it got what it asked for will fail later with a confusing 403 from the API. **Compare requested against granted, and log the difference.**

### D.4 ID token — decoded

Audience is your **`client_id`**. For the client only (§3.2).

```json
{
  "ver": 1,
  "jti": "ID.7d793037a0760186574b0282f2f435e7",
  "iss": "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
  "aud": "0oa1a2b3c4d5e6f7g8h9",
  "sub": "00u1a2b3c4d5e6f7g8h9",
  "iat": 1735689600,
  "exp": 1735690500,
  "auth_time": 1735689598,
  "amr": ["pwd", "mfa", "otp"],
  "idp": "00o1a2b3c4d5e6f7g8h9",
  "nonce": "7d793037a0760186574b0282f2f435e7",
  "at_hash": "eGhmZmZ4ZGZ...",
  "name": "Alice Chen",
  "preferred_username": "alice@contoso.com",
  "email": "alice@contoso.com",
  "email_verified": true,
  "groups": ["App-Finance", "App-Warehouse"]
}
```

| Claim | Use it for | Do **not** use it for |
|---|---|---|
| `sub` | The user's stable Okta ID | — |
| `aud` | Verifying the token is for **this client** | — |
| `name`, `email`, `preferred_username` | Displaying who is signed in | Authorization — email is mutable and spoofable upstream |
| `auth_time` | Deciding whether to force re-authentication | — |
| `amr` **[Okta]** | Detecting whether MFA was used, for step-up | Trusting it from an unvalidated token |
| `nonce` | Replay protection — must match what you sent | — |
| `at_hash` | Binding the ID token to the access token | — |
| `idp` **[Okta]** | Which upstream IdP authenticated the user | — |
| `groups` | UI gating only (§8.13) | **Server-side authorization** — use the access token's claims |

> ⚠️ **`sub` means different things in the two tokens, and this catches everyone.**
> - **ID token** `sub` = the Okta user ID (`00u…`).
> - **Access token** (Custom AS) `sub` = the user's **login**, typically their email.
>
> Joining your database on `sub` therefore gives you a *different key* depending on which token you read it from — and the access token's version **changes when the user's email changes**. Use **`uid`** (present in the access token) or the ID token's `sub` as your stable key, and never mix the two (§3.4).

> ⚠️ **`amr` is a claim about the past, not a live assertion.** It records how the user authenticated when the session started, possibly hours ago. For a genuinely sensitive operation, do not read `amr` — force a fresh authentication with `prompt=login` and `max_age`, then check `auth_time`.

### D.5 Access token — decoded

Full annotated breakdown is in **§3.4**. The essentials:

```json
{
  "ver": 1, "jti": "AT.xY3k9...",
  "iss": "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
  "aud": "api://apia",
  "sub": "alice@contoso.com",
  "iat": 1735689600, "exp": 1735690500,
  "cid": "0oa1a2b3c4d5e6f7g8h9",
  "uid": "00u1a2b3c4d5e6f7g8h9",
  "scp": ["openid", "profile", "apia.read"],
  "auth_time": 1735689598,
  "groups": ["App-Finance"]
}
```

**How to tell what kind of token you are holding** — useful in API middleware and in triage:

| Observation | Token kind |
|---|---|
| `aud` is `api://…` | Access token for an API |
| `aud` is `0oa…` (a client ID) | **ID token** — reject it at an API (§3.2) |
| `uid` and `sub` both present, `sub` looks like a login | User access token |
| No `uid`, `sub` == `cid` | **Client-credentials** token — a service, not a user (§7.2) |
| `iss` has no `/oauth2/{id}` segment | Org AS token — wrong server (§5.1) |

### D.6 Error responses

All error bodies follow [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2):

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed. Either the client or the client credentials are invalid."
}
```

Okta also returns its own richer envelope on some management and non-OAuth endpoints:

```json
{
  "errorCode": "E0000011",
  "errorSummary": "Invalid token provided",
  "errorLink": "E0000011",
  "errorId": "oaeQdc9BQpaSXanBTFRvTfDGA",
  "errorCauses": []
}
```

> ⚠️ **`errorId` is the single most valuable field when you open an Okta support ticket** — it identifies the exact request in Okta's own logs. Log it. It is not sensitive and contains no token material.

**Handling rules:**

| Rule | Why |
|---|---|
| Log `error`, `error_description`, and `errorId` | These are your diagnostics (§14.3) and contain no credentials |
| **Never** return `error_description` to the end user verbatim | It leaks configuration detail and is written for developers, not users |
| Never retry on `invalid_grant` | The code or refresh token is dead. Retrying can trigger rotation-reuse detection and invalidate the whole family (§5.6) |
| Retry with backoff **only** on `429` and `5xx` | Everything else is deterministic and will fail identically |
| Treat `429` as a rate-limit signal, not a transient blip | Check `X-Rate-Limit-Remaining` / `X-Rate-Limit-Reset` and back off hard (§7.7) |

### D.7 Introspection response

`POST /v1/introspect` — [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).

```json
{
  "active":     true,
  "scope":      "apia.read apia.write",
  "username":   "alice@contoso.com",
  "exp":        1735690500,
  "iat":        1735689600,
  "sub":        "alice@contoso.com",
  "aud":        "api://apia",
  "iss":        "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
  "jti":        "AT.xY3k9...",
  "token_type": "Bearer",
  "client_id":  "0oa1a2b3c4d5e6f7g8h9",
  "uid":        "00u1a2b3c4d5e6f7g8h9"
}
```

For a revoked, expired, or unknown token:

```json
{ "active": false }
```

> ⚠️ **`active: false` arrives with HTTP `200 OK`, not an error status.** Code that checks only the status code will treat a revoked token as valid. **Always branch on the `active` field.** This is a well-known source of authentication bypasses.

> ⚠️ **Introspection is a network call per request.** It gives you instant revocation (§11.4) at the cost of latency and a hard availability dependency on Okta — which is precisely the property §9.4 works to avoid. Apply it to one or two genuinely high-value endpoints if you need it. **Never make it your default validation path.**

### D.8 UserInfo response

`GET /v1/userinfo` with `Authorization: Bearer {access_token}`.

```json
{
  "sub":                "00u1a2b3c4d5e6f7g8h9",
  "name":               "Alice Chen",
  "preferred_username": "alice@contoso.com",
  "email":              "alice@contoso.com",
  "email_verified":     true,
  "zoneinfo":           "America/Los_Angeles"
}
```

Returns the OIDC claims permitted by the granted scopes. **You rarely need it** — the ID token already carries this, without a round trip. Reach for it only when profile data may have changed mid-session and you need it fresh.

### D.9 JWKS response

`GET /v1/keys` — the public keys your APIs validate with (§9.4).

```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "kid": "SxE5D3xzQCSFvFqQaQDqYQ0hDx8jFvKZaMPbBRl9pKA",
      "use": "sig",
      "e":   "AQAB",
      "n":   "wJ8N3Yx..."
    },
    { "kty": "RSA", "alg": "RS256", "kid": "9jNCe1lQhbfvVDDXqWXCDQ...", "use": "sig", "...": "..." }
  ]
}
```

**Multiple keys is the normal, healthy state** — it is how rotation works without downtime. The token's `kid` header selects which one to use.

> ⚠️ **This response is public by design and requires no authentication.** Fetching it is not a secret operation, and it is a perfectly good connectivity test from a server (§13.4). What matters is that you fetch it **over HTTPS from the configured issuer**, and never from a URL named inside a token (§12.2 rule 4).

### D.10 Revocation response

`POST /v1/revoke` returns **`200 OK` with an empty body** — for a valid token, an already-revoked token, and a token that never existed. This is [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) behaviour, deliberately designed so an attacker cannot use the endpoint to probe which tokens are real.

> ⚠️ **You cannot confirm a revocation succeeded from the response.** A `200` means "the request was well-formed", not "that token is now dead". Do not build logic that depends on distinguishing the two, and do not treat a non-200 as a reason to block sign-out (§11.1).

---

## Appendix E — What to store, where, and what must never be shared

### E.1 Storage matrix — desktop client

| Artifact | Store? | Where | Protection | Cleared when |
|---|---|---|---|---|
| **Refresh token** | ✅ Yes | `%LOCALAPPDATA%\Corp\{App}\{client_id}.tokens` | DPAPI `CurrentUser` | Sign-out, refresh failure, corrupt blob |
| **Device secret** (Appendix A) | ✅ Yes | Same store | DPAPI `CurrentUser` | Sign-out — revoke server-side too |
| **Access token** | ❌ **Never to disk** | Process memory only | — | Expiry, sign-out, process exit |
| **ID token** | ⚠️ Memory; persist only for logout | Process memory | — | Sign-out |
| **`code_verifier`** | ❌ Never | Memory, for the length of one flow | — | Immediately after token exchange |
| **Authorization code** | ❌ Never | Memory, single use | — | Immediately after redemption |
| **`state` / `nonce`** | ❌ Never | Memory, for one flow | — | After validation |
| **`client_id`** | ✅ Yes | `appsettings.json` | None needed — **not a secret** | — |
| **Issuer / audience / scopes** | ✅ Yes | `appsettings.json` | None needed | — |
| **Username for UI display** | ⚠️ Only if you need a "last user" hint | Config or registry | None | Sign-out |

### E.2 Storage matrix — API server

| Artifact | Store? | Where | Protection |
|---|---|---|---|
| **Client signing certificate** | ✅ Yes | `LocalMachine\My` | `NonExportable` private key + ACL (§6.6, §13.3) |
| **Cert thumbprint** | ✅ Yes | `appsettings.json` | None needed — an identifier, not a secret |
| **JWKS / discovery metadata** | ✅ Cached in memory | `ConfigurationManager` | — |
| **Exchanged (OBO) tokens** | ⚠️ Memory cache, keyed by subject | `IMemoryCache` | Never to disk, never to a shared cache (E.4) |
| **Client-credentials tokens** | ⚠️ Memory cache, keyed by scope | `IMemoryCache` | Never to disk |
| **Inbound access tokens** | ❌ **Never** | Request scope only | Never persisted, never logged |
| **Client secret** | ❌ Not applicable | — | You use `private_key_jwt` instead (§4.4) |

> ⚠️ **The rule that covers almost every case: persist only what you cannot re-obtain, and only when losing it costs the user something.** A refresh token is worth persisting — losing it means an interactive sign-in. An access token is not — it expires in 15 minutes and can be re-minted silently. Persisting it adds a disk-resident bearer credential and buys nothing.

### E.3 Public by design — do **not** over-protect these

Teams routinely treat these as secrets, then cannot debug anything because nobody may see the configuration. They are all published, by design, in the discovery document or in the client binary:

| Value | Why it is public |
|---|---|
| `client_id` | Sent in every `/authorize` URL, visible in the browser address bar |
| Issuer URL | Published in every token's `iss` |
| Audience (`api://apia`) | Published in every token's `aud` |
| Scope names | Published in `scopes_supported` |
| Redirect URIs | Visible in the address bar; registered publicly |
| JWKS public keys | Served unauthenticated at `/v1/keys` (D.9) |
| Discovery document | Served unauthenticated |
| Certificate **thumbprint** | An identifier for a public certificate |

> ⚠️ **A public client has no secrets — that is the definition, not a weakness.** PKCE exists precisely because `AppA` cannot hold one (§4.1). If someone proposes "embedding a client secret in the WPF app to make it more secure", the answer is that a decompiler finds it in under a minute, and shipping one creates a *false* sense of security while adding a credential to rotate. Refuse it.
>
> The corollary: **do not put a `client_secret` in a desktop `appsettings.json`.** If one is there, the app is registered as the wrong type in Okta (§6.5).

### E.4 The sharing matrix — what must never cross which boundary

| Artifact | `AppA` ↔ `AppB` | Client → Server | `ApiA` ↔ `ApiB` | → Logs / telemetry | → Source control | → Support bundle |
|---|---|---|---|---|---|---|
| Refresh token | ❌ **Never** (§4.7) | ❌ Never | ❌ Never | ❌ Never | ❌ Never | ❌ Never |
| Access token (`aud=api://apia`) | ❌ Never | ✅ To `ApiA` only | ❌ **Never** (§7.5) | ❌ Never | ❌ Never | ❌ Never |
| ID token | ❌ Never* | ❌ Never | ❌ Never | ❌ Never | ❌ Never | ❌ Never |
| `code_verifier` / auth code | ❌ Never | ❌ Never | ❌ Never | ❌ Never | ❌ Never | ❌ Never |
| Device secret | ⚠️ *Only* under Appendix A | ❌ Never | ❌ Never | ❌ Never | ❌ Never | ❌ Never |
| Client assertion (`private_key_jwt`) | ❌ N/A | ❌ Never | ❌ Never | ❌ Never | ❌ Never | ❌ Never |
| Signing **private key** | ❌ Never | ❌ Never | ❌ **Never** — one key per API | ❌ Never | ❌ Never | ❌ Never |
| Token **`jti` / `sub` / `uid` / `exp`** | ✅ Fine | ✅ Fine | ✅ Fine | ✅ **Log these** | ✅ Fine | ✅ Fine |
| `client_id`, issuer, audience | ✅ Fine | ✅ Fine | ✅ Fine | ✅ Fine | ✅ Fine | ✅ Fine |
| Okta `errorId` | ✅ Fine | ✅ Fine | ✅ Fine | ✅ **Log it** (D.6) | ✅ Fine | ✅ Fine |

\* `AppB` reads `AppA`'s ID token **only** in the Native SSO exchange (Appendix A), and only via the device-secret mechanism. Never by reading `AppA`'s token file.

**The five boundaries, stated plainly:**

1. **`AppA` ↔ `AppB`.** Separate `client_id`s, separate token stores, separate DPAPI blobs, separate files (§8.6). They share an Okta **session**, never a **credential** (§2.1). The only sanctioned exception is the Native SSO device secret, and A.4 explains why that is a real trade rather than a free upgrade.
2. **Client → Server.** The client sends exactly one access token, addressed to that server. It never sends the refresh token, the ID token, or the `code_verifier`. (§7.3 Pattern 3 is the sole exception, and it sends a *second access token* in a distinct header — never a refresh token.)
3. **`ApiA` ↔ `ApiB`.** Never the inbound token (§7.5). Always a token minted for the destination — by exchange (§7.1) or by client credentials (§7.2). Separate signing certificates: one compromised API host must not yield the other's service identity.
4. **Application → logs and telemetry.** Identifiers yes, credentials never (§12.5). The redaction regex is a safety net, not a substitute for not logging them.
5. **Production ↔ non-production.** Separate Okta tenants, separate client IDs, separate certificates. Never point a dev build at the production tenant "just to test" — it puts production tokens on developer machines with no controls around them.

### E.5 Source control

```gitignore
# Never commit
*.pfx
*.p12
*.key
appsettings.*.Local.json
**/secrets.json
*.tokens
```

Commit `appsettings.json` with **placeholders**, not real IDs. Real values come from environment-specific transforms at deploy time.

> ⚠️ **A leaked `client_id` is not an incident. A leaked signing key is.** Keep the distinction clear in your incident runbook, or a routine config commit gets escalated as a breach while an actual key exposure goes unnoticed. Reserve the alarm for: private keys (`.pfx`/`.p12`), refresh tokens, device secrets, and any live JWT.

### E.6 Crash dumps, error reporting, and telemetry

The most-overlooked leak path in a desktop application. Access and ID tokens live in process memory by design (E.1) — which means a **full memory dump contains live credentials**.

| Control | Action |
|---|---|
| Crash reporting | Configure **minidumps**, not full-memory dumps |
| Unhandled exception handlers | Scrub with the §12.5 regex before reporting |
| Telemetry (App Insights, Sentry…) | Scrub HTTP headers; most SDKs capture `Authorization` **by default** |
| `HttpClient` diagnostic logging | `Microsoft.Extensions.Http` logs request headers at `Trace` — never enable `Trace` in production |
| User-initiated "send diagnostics" | Never include the token store file or a process dump |

> ⚠️ **The default configuration of most telemetry SDKs captures request headers, including `Authorization`.** This is the single most common way a working access token ends up in a third-party SaaS, indexed and retained. **Verify the redaction actually works by inspecting a real captured trace** — do not assume it because the SDK documentation mentions a scrubber.

### E.7 Multi-user and shared machines

| Scenario | Behaviour | Action |
|---|---|---|
| Two Windows users, one PC | DPAPI `CurrentUser` isolates them automatically | None — it works correctly |
| Shared kiosk account | **All users share one token store** | Use `SignOutScope.Global` (§11.2) on exit; consider not persisting the refresh token at all |
| Roaming profiles | Tokens follow the user across machines | Usually desirable; add machine entropy if your posture forbids it (§13.7) |
| RDP / Citrix multi-session | Each session has its own profile — isolated | None |
| Fast user switching | Isolated by profile | None |

> ⚠️ **On a shared or kiosk account, disable refresh-token persistence entirely.** Every user of that Windows account can otherwise resume the previous user's session simply by launching the app. Make it a configuration flag (`PersistSession: false`) so the same binary serves both deployment models, and default it to `false` for any machine class you do not control.

---

## Appendix F — Do's and don'ts

The consolidated card. Every row links to the section that explains it. Suitable for a code-review checklist or a team wiki page.

### F.1 Protocol and flow

| | Practice | Why |
|---|---|---|
| ✅ | Authorization Code + PKCE `S256` | Only safe flow for a public client (§4.1) |
| ✅ | System browser for `/authorize` | SSO cookie, anti-phishing, passkeys (§4.2) |
| ✅ | Loopback `127.0.0.1` redirect on a fixed port pool | No registry writes, no scheme hijacking (§4.3) |
| ✅ | Validate `state` before reading any other parameter — including on errors | CSRF (§D.2) |
| ✅ | Try `prompt=none` first for a silent path, fall back to interactive | No surprise browser windows (§8.9) |
| ❌ | Embedded WebView2 for sign-in | Breaks SSO, enables phishing, blocks MFA (§4.2) |
| ❌ | ROPC / `password` grant | Deprecated; destroys SSO and MFA (§4.5) |
| ❌ | Implicit or hybrid `response_type` | Tokens leak via URL fragments (§4.6) |
| ❌ | `localhost` instead of `127.0.0.1` | Can be redirected by DNS/hosts (§4.3) |
| ❌ | Retry a failed `/token` call on `invalid_grant` | Code is dead; can trigger rotation-reuse detection (§D.6) |

### F.2 Tokens and claims

| | Practice | Why |
|---|---|---|
| ✅ | Treat the access token as **opaque** in the client | Format is not contractual (§3.2) |
| ✅ | Read UI identity from the **ID token** | That is what it is for (§3.2) |
| ✅ | Use `expires_in` from the token response for refresh timing | The only expiry a client should read (§D.3) |
| ✅ | Use `uid` (or the ID token's `sub`) as your stable user key | Access-token `sub` is the login and changes (§D.4) |
| ✅ | Handle `scp` as both an array and a space-delimited string | Okta emits an array; others differ (§9.3) |
| ✅ | Compare requested vs granted `scope` and log the difference | Okta narrows silently (§D.3) |
| ❌ | Decode the access token in the client | Couples you to a format Okta may change (§3.2) |
| ❌ | Send an ID token to an API, or accept one at an API | Wrong audience; classic bypass (§3.2) |
| ❌ | Put fine-grained permissions in the token | Stale, bloated, IdP-coupled (§5.5) |
| ❌ | Emit an unfiltered `groups` claim | Header overflow + org-chart leak (§5.5) |
| ❌ | Trust `amr` for a sensitive action | Describes the past; force re-auth instead (§D.4) |

### F.3 Storage

| | Practice | Why |
|---|---|---|
| ✅ | Persist only the refresh token (and device secret), DPAPI-encrypted | Everything else is cheaply re-obtainable (§E.2) |
| ✅ | One token store per `client_id` | `AppA` and `AppB` must not read each other's (§8.6) |
| ✅ | Write-then-move when saving | A truncated file forces a needless re-auth (§8.6) |
| ✅ | Persist the rotated refresh token **immediately** on receipt | A crash in between leaves a dead token (§8.8) |
| ✅ | Delete the store on any decrypt/parse failure | Machine rebuild or roam — recover, do not crash (§8.6) |
| ❌ | Write an access token or ID token to disk | Disk-resident bearer credential, no rotation (§12.3) |
| ❌ | Ship a `client_secret` in a desktop app | Decompilable in a minute; false security (§E.3) |
| ❌ | Share a token cache between apps | Weakest app compromises the strongest (§4.7) |
| ❌ | Persist tokens on a shared/kiosk account | Next user resumes the previous session (§E.7) |
| ❌ | Treat `client_id` or the issuer as a secret | Public by design; over-protecting blocks debugging (§E.3) |

### F.4 API token validation

| | Practice | Why |
|---|---|---|
| ✅ | `ValidateAudience = true` with an exact `ValidAudience` | Rule 1; the whole security boundary (§9.2) |
| ✅ | `ValidateIssuer = true` with an exact `ValidIssuer` | Blocks tokens from another AS (§9.2) |
| ✅ | Pin `ValidAlgorithms` to `RS256` | Blocks `alg` confusion and `none` (§9.2) |
| ✅ | `RequireHttpsMetadata = true` **everywhere** | Plaintext metadata = attacker-supplied keys (§9.2) |
| ✅ | `MapInboundClaims = false` | Otherwise `sub` lookups silently return null (§9.2) |
| ✅ | `ClockSkew = 30s` + monitored NTP | 5-minute default is too wide for 15-minute tokens (§9.2, §13.5) |
| ✅ | Set a `FallbackPolicy` — deny by default | A forgotten `[Authorize]` fails closed (§9.3) |
| ✅ | Warm the metadata cache at startup and fail loudly | Beats failing the first user request (§9.4) |
| ✅ | Branch on `active` when introspecting | `active:false` returns HTTP 200 (§D.7) |
| ❌ | `ValidateAudience = false` — under any justification | Accepts every token in the org (§9.2) |
| ❌ | Trust `jku`, `x5u`, or `jwk` headers from a token | Attacker names their own key source (§12.2) |
| ❌ | Call Okta to validate on the request path | Latency + availability coupling (§9.4) |
| ❌ | Refresh JWKS manually per request | Defeats the built-in rate limiting (§9.4) |
| ❌ | Return 401 for an authorization failure | Sends the client into a pointless refresh loop (§9.6) |

### F.5 Service-to-service delegation

| | Practice | Why |
|---|---|---|
| ✅ | OBO token exchange for user-initiated calls | Preserves identity, satisfies both rules (§7.1) |
| ✅ | Client credentials for background work | Correct authority when no user is involved (§7.2) |
| ✅ | Separate typed clients for user vs background calls | Makes the wrong choice visible at the call site (§9.5) |
| ✅ | Cache exchanged tokens keyed by a **hash of the subject token** | Or you serve Alice's token to Bob (§7.1) |
| ✅ | Cap a delegated token's cache TTL at the subject's `exp` | Delegated authority must not outlive its source (§7.1) |
| ✅ | Register a delegation depth guard on every outbound client | Mutual calls can cycle (§7.7) |
| ✅ | `private_key_jwt` with a non-exportable key | No secret to transport or leak (§4.4) |
| ❌ | Forward the inbound token to a different API | Confused deputy (§7.5) |
| ❌ | Use a service token to serve a user request | Silent privilege escalation for every user (§7.2) |
| ❌ | Share one signing certificate across both APIs | One host compromise yields both identities (§E.4) |
| ❌ | Collapse both APIs onto one audience for convenience | Removes the containment boundary (§7.4) |

### F.6 Okta configuration

| | Practice | Why |
|---|---|---|
| ✅ | Custom Authorization Server | Org AS cannot do your audiences or scopes (§5.1) |
| ✅ | One `client_id` per application | Revocation, scoping, and audit all depend on it (§2.1) |
| ✅ | Named authorization servers in production, not `default` | `default` is shared; its policies drift (§5.1) |
| ✅ | Filter the `groups` claim with a prefix | Token size and information disclosure (§5.5) |
| ✅ | Per-client access policies, catch-all deny last | Rules are first-match-wins (§6.7) |
| ✅ | Access token ≤ 15 min; rotation on with a 30 s grace | Lifetime *is* your revocation window (§5.6) |
| ✅ | Enable persistent session cookie across browser restarts | Otherwise desktop SSO silently breaks (§10.1) |
| ✅ | Verify Token Preview before writing code | Same policy engine; fails in 30 s not 3 days (§6.8) |
| ✅ | Register a second signing key before rotating | Rotating in one step means downtime (§6.6) |
| ❌ | Define a `*.admin` or `full_access` scope | Becomes the universal default within a year (§5.4) |
| ❌ | Mark scopes as default/implicitly granted | Grant surface stops being auditable (§6.3) |
| ❌ | Enable grants you do not use on an app integration | Especially `password` (§D.1) |
| ❌ | Set rotation grace to 0 | A legitimate retry then looks like theft (§5.6) |

### F.7 Client application

| | Practice | Why |
|---|---|---|
| ✅ | Serialise refresh with a semaphore, double-checked | Concurrent refresh trips rotation-reuse detection (§8.7) |
| ✅ | Refresh proactively ~90 s before expiry | A reactive refresh costs the user a failed request (§8.8) |
| ✅ | Exactly one 401 retry, marked | Otherwise an unfixable 401 loops forever (§8.10) |
| ✅ | Clone the request before retrying | `HttpRequestMessage` cannot be sent twice (§8.10) |
| ✅ | Token handler **inside** the retry policy | Or a retry reuses the stale token (§8.10) |
| ✅ | Authenticate in `OnInitialized`, not a constructor | Constructors cannot await (§8.11) |
| ✅ | Re-check the session on `PowerModes.Resume` | Laptops sleep; timers do not fire (§8.8) |
| ✅ | Return focus to the app after the browser redirect | The top UX complaint about correct SSO (§8.5) |
| ❌ | Expose an `AccessToken` property | Invites a stale cached copy (§8.3) |
| ❌ | Treat client-side gating as security | Re-enforce every rule server-side (§8.13) |
| ❌ | Block the UI thread on a token call | Deadlock or an unauthenticated flash (§8.11) |

### F.8 Logging, telemetry, and diagnostics

| | Practice | Why |
|---|---|---|
| ✅ | Log `jti`, `sub`/`uid`, `exp`, `cid`, `kid`, and Okta `errorId` | Full diagnosis without credentials (§12.5, §D.6) |
| ✅ | Log every authorization denial with policy name and missing scope | Otherwise 403s are unattributable (§12.5) |
| ✅ | Run a central redaction regex | Catches the mistake you did not anticipate (§12.5) |
| ✅ | Minidumps, not full-memory dumps | Full dumps contain live tokens (§E.6) |
| ✅ | Verify telemetry redaction on a real captured trace | SDKs capture `Authorization` by default (§E.6) |
| ✅ | Check the Okta System Log **first** | It records the policy decision your app never sees (§14.1) |
| ❌ | Log any token, code, verifier, or assertion | (§12.5) |
| ❌ | Paste a production token into jwt.io | Sending a live credential to a third party (§14.2) |
| ❌ | Return `error_description` to end users | Leaks configuration detail (§D.6) |
| ❌ | Enable `Trace` logging for `HttpClient` in production | Logs request headers, tokens included (§E.6) |

### F.9 Operations

| | Practice | Why |
|---|---|---|
| ✅ | App pool **Load User Profile = True** | Or every outbound call fails cryptically (§13.2) |
| ✅ | Grant the pool identity read on the cert private key, and health-check it | Silently lost on cert reinstall (§13.3) |
| ✅ | Verify Okta egress **from the server itself** | TLS interception is the #1 environment bug (§13.4) |
| ✅ | Monitor and alert on clock skew | Most confusing failure mode in the document (§13.5) |
| ✅ | Okta health check = **Degraded**, not Unhealthy | Cached keys survive an Okta outage (§14.4) |
| ✅ | Alert on **any** `system.org.rate_limit.warning` | Possible delegation cycle; tenant-wide blast radius (§7.7) |
| ✅ | Alert at 30 days on certificate expiry | Rotation becomes planned, not an outage (§14.4) |
| ❌ | Raise header limits to fit a bloated token | Fix the `groups` filter instead (§13.6) |
| ❌ | Point a dev build at the production tenant | Production tokens on developer machines (§E.4) |
| ❌ | Let the app pool idle-timeout | Discards the JWKS cache (§13.2) |

### F.10 Testing

| | Practice | Why |
|---|---|---|
| ✅ | Assert the §12.2 non-negotiables in a CI test | Stops a Friday-afternoon relaxation (§15.2) |
| ✅ | Test what must be **rejected**, not what is accepted | The happy path is covered by every manual run (§15.3) |
| ✅ | Override only the **key source** in the test host | Or you test a config you never deploy (§15.3) |
| ✅ | Assert token **contents** in integration tests | `aud`, `sub`, `scp` are the point (§15.4) |
| ✅ | Run manual cases 4, 11, 12 | The ones teams skip and users find (§15.5) |
| ❌ | Relax validation "to make the test pass" | Makes the CI guards worthless (§15.3) |
| ❌ | Automate a browser flow with a real user's password | Reintroduces exactly what §4.5 removes (§15.4) |
| ❌ | Commit a real token as a test fixture | A live credential in source control (§E.5) |
## Appendix G — Glossary

| Term | Meaning |
|---|---|
| **Access token** | Credential addressed to one API. Opaque to the client. |
| **Actor / `act`** | The service acting on a user's behalf in a delegated token. |
| **Assurance policy** | Okta policy defining the authentication strength required. |
| **`aud` (audience)** | The single intended recipient of a token. The core of §3.3. |
| **Authorization Server** | The component that issues tokens. Org or Custom in Okta (§5.1). |
| **Bearer token** | A token where possession alone grants access. Contrast: DPoP. |
| **`cid`** | Okta claim: the client ID that requested the token. |
| **Client assertion** | A signed JWT proving a confidential client's identity (§4.4). |
| **Confused deputy** | A privileged component tricked into acting on an unauthorised request (§7.5). |
| **Custom AS** | Okta authorization server for **your** APIs. Required here. |
| **Device secret** | Okta Native SSO credential shared between native apps (Appendix A). |
| **DPAPI** | Windows Data Protection API. User- or machine-scoped encryption (§8.6). |
| **DPoP** | Sender-constrained tokens, RFC 9449 (§12.4). |
| **ID token** | Proof that a login occurred. For the client only (§3.2). |
| **Introspection** | Asking the IdP whether a token is currently valid. RFC 7662. |
| **JWKS** | JSON Web Key Set — the IdP's public signing keys (§9.4). |
| **`kid`** | Key ID; selects which JWKS key signed a token. |
| **Loopback redirect** | Native-app redirect to `127.0.0.1` (§4.3). |
| **OBO** | On-Behalf-Of; delegation preserving user identity (§7.1). |
| **PKCE** | Proof Key for Code Exchange, RFC 7636 (§4.1). |
| **`prompt=none`** | Ask the IdP to succeed silently or fail — never prompt (§8.9). |
| **Public client** | A client that cannot keep a secret. All four desktop scenarios. |
| **Refresh token rotation** | Each use invalidates the old token; enables theft detection (§5.6). |
| **Resource indicator** | `resource` parameter selecting the target audience, RFC 8707. |
| **`scp`** | Okta claim: granted scopes, as a JSON **array** (§3.4). |
| **Token exchange** | RFC 8693; trades one token for another (§7.1). |
| **Trusted server** | Okta relationship permitting cross-AS OBO exchange (§5.7). |
| **`uid`** | Okta claim: immutable Okta user ID. Prefer over `sub` (§3.4). |

---

## Appendix H — References

### Specifications

| Spec | Relevance |
|---|---|
| [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) | The framework |
| [RFC 6750 — Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750) | `Authorization` header, `WWW-Authenticate` errors (§9.6) |
| [RFC 7009 — Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009) | `/v1/revoke` (§11.1) |
| [RFC 7517 — JSON Web Key](https://datatracker.ietf.org/doc/html/rfc7517) | JWKS format (§6.6, §9.4) |
| [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) | Token format and claims |
| [RFC 7523 — JWT Client Authentication](https://datatracker.ietf.org/doc/html/rfc7523) | `private_key_jwt` (§4.4, §7.1) |
| [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636) | **§4.1 — mandatory** |
| [RFC 7807 — Problem Details](https://datatracker.ietf.org/doc/html/rfc7807) | API error responses (§9.6) |
| [RFC 8252 — OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252) | **§4.2, §4.3 — the governing BCP** |
| [RFC 8414 — AS Metadata](https://datatracker.ietf.org/doc/html/rfc8414) | `.well-known` discovery (§6.2) |
| [RFC 8693 — Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) | **§7.1 — OBO delegation** |
| [RFC 8707 — Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707) | `resource` parameter (§8.9) |
| [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449) | Sender-constrained tokens (§12.4) |
| [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) | Why ROPC and implicit are rejected (§4.5, §4.6) |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID tokens, `nonce`, `prompt` |
| [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | Global sign-out (§11.2) |
| [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Server-side session termination (§11.3) |

### Okta documentation

| Topic | Link |
|---|---|
| Authorization servers — Org vs Custom | https://developer.okta.com/docs/concepts/auth-servers/ |
| API Access Management | https://developer.okta.com/docs/concepts/api-access-management/ |
| Create an authorization server | https://developer.okta.com/docs/guides/customize-authz-server/main/ |
| Create an authorization server (Admin) | https://help.okta.com/oie/en-us/Content/Topics/Security/api-config-auth-server.htm |
| Create API access scopes | https://help.okta.com/oie/en-us/Content/Topics/Security/api-config-scopes.htm |
| OAuth 2.0 claims and scopes | https://developer.okta.com/docs/concepts/oauth-claims/ |
| Customize tokens with a groups claim | https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/ |
| **On-Behalf-Of Token Exchange** | https://developer.okta.com/docs/guides/set-up-token-exchange/main/ |
| **Add trusted servers** | https://help.okta.com/oie/en-us/content/topics/security/api-add-trusted-servers.htm |
| Token lifecycle (exchange, refresh, revoke) | https://developer.okta.com/docs/concepts/token-lifecycles/ |
| Refresh tokens and rotation | https://developer.okta.com/docs/guides/refresh-tokens/main/ |
| **Configure SSO for Native apps** | https://developer.okta.com/docs/guides/configure-native-sso/main/ |
| Native SSO (concept walkthrough) | https://developer.okta.com/blog/2021/11/12/native-sso |
| Client authentication methods | https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth |
| Build a JWT for client authentication | https://developer.okta.com/docs/guides/build-self-signed-jwt/java/main/ |
| OAuth for Okta with a service app | https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/ |
| Key management | https://developer.okta.com/docs/guides/key-management/main/ |
| **JWT validation for .NET** | https://developer.okta.com/code/dotnet/jwt-validation/ |
| Configure DPoP | https://developer.okta.com/docs/guides/dpop/nonoktaresourceserver/main/ |
| DPoP explained | https://developer.okta.com/blog/2024/09/05/dpop-oauth |
| System Log event types | https://developer.okta.com/docs/reference/api/event-types/ |
| Authorization Servers Management API | https://developer.okta.com/docs/api/openapi/okta-management/management/tags/authorizationserver |
| Terraform provider | https://registry.terraform.io/providers/okta/okta/latest/docs |

### .NET, Prism, Telerik

| Topic | Link |
|---|---|
| `Duende.IdentityModel.OidcClient` | https://github.com/DuendeSoftware/foss |
| IdentityModel (token client) | https://identitymodel.readthedocs.io/ |
| JWT bearer authentication | https://learn.microsoft.com/aspnet/core/security/authentication/jwt |
| Policy-based authorization | https://learn.microsoft.com/aspnet/core/security/authorization/policies |
| `IHttpClientFactory` and handlers | https://learn.microsoft.com/aspnet/core/fundamentals/http-requests |
| DPAPI / `ProtectedData` | https://learn.microsoft.com/dotnet/api/system.security.cryptography.protecteddata |
| Host ASP.NET Core on IIS | https://learn.microsoft.com/aspnet/core/host-and-deploy/iis/ |
| Prism 8 documentation | https://prismlibrary.com/docs/ |
| Prism dialog service | https://prismlibrary.com/docs/wpf/dialog-service.html |
| Telerik UI for WPF | https://docs.telerik.com/devtools/wpf/introduction |
| `RadBusyIndicator` | https://docs.telerik.com/devtools/wpf/controls/radbusyindicator/overview |
| `RadDesktopAlert` | https://docs.telerik.com/devtools/wpf/controls/raddesktopalert/overview |

---

## Next steps

This document is the specification. The demo is built from it, in this order:

1. **Settle the two open decisions** — the §5.2 topology and the §7 delegation pattern. Run the 30-minute spike in §7.6; it settles §7 on evidence.
2. **Configure Okta** per §6, filling in [Appendix B](#appendix-b--configuration-reference-sheet) as you go. Do not write code until Token Preview (§6.8) is clean.
3. **Build `Corp.Identity.Client`** (§8.1–§8.10) and wire `AppA` to `ApiA` end to end. One app, one API, browser sign-in working.
4. **Add `AppB` and `ApiB`.** Verify cross-app SSO (§10) — manual test cases 3 and 4 in §15.5.
5. **Implement the chosen §7 pattern** for `ApiA ↔ ApiB`, with the depth guard from §7.7 in place from the first commit.
6. **Write the negative tests** (§15.3) and the CI guards (§15.2) alongside the code, not after it.
7. **Work the go-live checklist** (§16).
