# Demo solution

The runnable companion to [README.md](README.md). The README is the specification; this
is the implementation, and every non-obvious decision in the code points back to a README
section by number.

> **Status:** builds clean, **42/42 tests pass**, and the full delegation chain runs end to
> end against a local IdP with no Okta tenant required.

---

## Layout

```
SSO.sln
├── src/
│   ├── Corp.Identity.Core/       Desktop auth: PKCE, loopback, DPAPI, refresh. No UI
│   │                             framework, no third-party package — Microsoft only
│   ├── Corp.Identity.Wpf/        Dialogs, busy overlay, focus, crash handling. No Prism
│   ├── Corp.Identity.Prism/      OPTIONAL Prism glue: module, navigation guard
│   ├── Corp.Api.Security/        Shared API auth: validation + §7 delegation patterns
│   ├── AppA/  AppB/              WPF clients (.NET 8, Prism 8, Velopack)
│   └── ApiA/  ApiB/              ASP.NET Core APIs that call each other, both directions
├── tools/
│   └── DevIdp/                   Local stand-in for Okta — run everything with no tenant
├── tests/
│   ├── Corp.Api.Security.Tests/  Negative token tests, CI guards, end-to-end delegation
│   └── Corp.Identity.Core.Tests/ PKCE vectors, port failover, ID token rejection cases
├── infra/okta/                   Terraform for the real tenant
└── build/
    ├── publish.ps1               Velopack packaging
    └── register-uri-scheme.ps1   OPTIONAL, not used — see "About the registry"
```

Both WPF apps share one authentication library; both APIs share one security library.

### Hosting the identity stack in another application

`Corp.Identity.Core` is standalone and has no dependency outside Microsoft's own packages
(`Microsoft.IdentityModel.Protocols.OpenIdConnect`, `Microsoft.Extensions.*`,
`System.Security.Cryptography.ProtectedData`). Any WPF application wires it up with:

```csharp
services.AddCorpIdentity(configuration, applicationName: "AppA", WpfIdentityExtensions.FocusRestorer);
services.AddCorpIdentityWpf(() => ShellViewModel.Instance);
services.AddCorpApiClient("ApiA");     // named HttpClient, tokens attached
```

A Prism host calls `registry.RegisterIdentity(configuration, "AppA", busyHost, "ApiA", "ApiB")`
instead, which composes exactly the same stack and hands the singletons to Prism.
`Corp.Identity.Prism` is the only assembly with a third-party dependency; an application
that does not use Prism never references it.
Nothing is duplicated — divergent copies of auth code become a security bug in whichever
copy gets less attention (README §8.1).

---

## Run it in three commands

No Okta tenant needed. `tools/DevIdp` is a local authorization server that speaks the same
protocol.

```bash
dotnet run --project tools/DevIdp     # https://localhost:7100
dotnet run --project src/ApiA         # https://localhost:7201
dotnet run --project src/ApiB         # https://localhost:7202
dotnet run --project src/AppA
```

The `Development` configuration in each project already points at DevIdp. Sign in as
**alice@contoso.com** (App-Finance + App-Warehouse) or **bob@contoso.com** (App-Warehouse
only) — the difference between them is what makes §7 visible.

If the browser complains about the certificate, trust the ASP.NET dev cert once:

```bash
dotnet dev-certs https --trust
```

### About DevIdp

⚠️ **Development only.** It authenticates nobody, checks no credentials, and signs with a
key generated at startup. It exists so the flows in README §7 and §10 can be exercised and
debugged before a tenant exists.

It deliberately reproduces Okta's *shapes*, because those are what break code:

| | |
|---|---|
| Two authorization servers, one per API | README §5.2 Variant B |
| `scp` and `groups` as JSON **arrays** | README §3.4 |
| Access-token `sub` = login; ID-token `sub` = user id | README §D.4 — the mismatch that catches everyone |
| `uid` and `cid` claims | README §D.5 |
| Rotating refresh tokens with replay detection | README §5.6 |
| Trusted-server checks on token exchange | README §5.7 |
| A session cookie, so the second app signs in silently | README §10.1 |
| `prompt=none` returning `login_required` | README §8.9 |

---

## What to actually look at

### AppA — the delegation explorer

| Button | Endpoint | What it shows |
|---|---|---|
| **Who am I? (ApiA)** | `GET /orders/whoami` | How ApiA sees your token: `sub`, `uid`, `cid`, `scp`, `groups` |
| **List orders** | `GET /orders` | Scope check *plus* per-record group filtering — scopes are necessary, never sufficient (README §9.3) |
| **ApiA → ApiB (on behalf of me)** | `GET /orders/{id}/billing` | The delegated call, using whichever §7 pattern is configured |
| **ApiA → ApiB (service identity)** | `GET /orders/reconcile` | The same hop as a *service*, with no user at all |

### AppB — the return direction

AppB is a separate Okta client with its own tokens, not a copy of AppA.

| Button | Endpoint | What it shows |
|---|---|---|
| **Who am I? (ApiB)** | `GET /invoices/whoami` | AppB's own token, from a different authorization server |
| **Get invoice** | `GET /invoices/{id}` | Requires `App-Finance`: Alice succeeds, Bob is denied |
| **ApiB → ApiA** | `GET /invoices/{id}/order-context` | The return direction — needs its own trusted-server entry (README §5.7) |
| **Trip the cycle guard** | `GET /invoices/cycle-demo` | Drives ApiB → ApiA → ApiB until the depth guard returns **508** (README §7.7) |

### The exercises that teach the most

**1. Delegation preserves identity.** Click **Who am I? (ApiA)**, note the subject. Click
**ApiA → ApiB (on behalf of me)**: ApiB reports the *same subject*, but `callingClientId`
is now ApiA's service client. The user survived the hop; the acting service is recorded.

**2. A service token has no user.** Click **ApiA → ApiB (service identity)**:
`isServicePrincipal` is `true` and there is *no subject*. ApiB is authorising the service,
and your permissions were never consulted — which is exactly why §7.2 says never to use
this shape for a user-initiated request.

**3. The downstream API does not trust the upstream one.** Sign out, sign in as
**bob@contoso.com**, and click **ApiA → ApiB** again. ApiA is happy to make the call; ApiB
returns 403, because the delegated token carries *Bob's* groups rather than ApiA's opinion
of them. Forwarding ApiA's own token would have destroyed exactly this property (README §7.5).

**4. Cross-app SSO.** With AppA running, launch AppB. A browser window flashes and you are
*not* prompted — the DevIdp session cookie was reused, and AppB received its own separate
tokens (README §10.1).

**5. The cycle guard.** In AppB, click **Trip the cycle guard**. Every hop is individually
valid and nothing in OAuth stops it; the depth guard does, at 508. Unguarded this can
exhaust the org-wide Okta `/token` rate limit and block sign-in for unrelated applications
(README §7.7).

### Switching delegation pattern

```jsonc
// src/ApiA/appsettings.Development.json
"Delegation": { "Pattern": "OnBehalfOf" }   // or "ClientRelayed"
```

Both work. Under `ClientRelayed`, AppA acquires a **second** access token for `api://apib`
and relays it in `X-Downstream-Authorization`; ApiA forwards that instead of exchanging
(README §7.3, §8.9). Watch the DevIdp log: under `OnBehalfOf` you see a token-exchange
call, under `ClientRelayed` you see a second authorize round trip from the desktop.

Pattern 2 (client credentials) is not a setting — it is a *separate named client*, chosen
per call site. `OrdersController.Billing` uses the user client; `OrdersController.Reconcile`
uses the background one. Two distinct clients, deliberately, so the most damaging mistake
in §7 is visible in review rather than buried in a handler (README §9.5).

---

## Tests

```bash
dotnet test tests/Corp.Api.Security.Tests
```

**42 tests**, weighted where README §15.3 says they should be — towards what must be
**rejected**.

| Suite | Covers |
|---|---|
| `TokenValidationTests` | Wrong audience, ID token at an API, foreign issuer, expired, not-yet-valid, unknown key, HMAC `alg` confusion, tampered payload, missing scope (403 not 401), service token on a user-only endpoint |
| `ConfigurationGuardTests` | The README §12.2 non-negotiables, as build failures |
| `ClientAssertionTests` | `private_key_jwt`: audience is the token endpoint, RS256, verifies against the public key, unique `jti`, short lifetime, and that the dev factory refuses a non-local endpoint |
| `DelegationDepthTests` | Header increment, refusal at the limit, malformed header treated as zero, and that a simulated cycle terminates |
| `EndToEndDelegationTests` | **The real chain**: DevIdp issues a token, ApiA validates and delegates, ApiB validates the delegated token and enforces its own authorization — including Bob being denied and the cycle tripping 508 |

The end-to-end suite runs all three hosts in-process and wires them to each other with
`HttpClient` instances backed by their own test servers, so no ports are bound.

---

## Going to a real Okta tenant

1. **`infra/okta/`** — Terraform for the whole Variant B topology: groups, two
   authorization servers, scopes, filtered groups claims, two native apps with all
   loopback redirect URIs, two service identities on `private_key_jwt`, assignments, and
   access policies with 15-minute tokens and rotating refresh.

   ```bash
   cd infra/okta
   cp terraform.tfvars.example terraform.tfvars   # then edit
   export OKTA_API_TOKEN=...
   terraform init && terraform apply
   ```

   `terraform output manual_steps_remaining` lists the four things Terraform cannot
   reliably cover — trusted servers, the Token Exchange grant, the persistent session
   cookie, and verifying Token Preview.

2. **Fill in the four `appsettings.json` files** from the Terraform outputs (they map
   one-to-one onto README Appendix B). Every placeholder reads `REPLACE-ME`, and the
   applications refuse to start with a clear message if you miss one.

3. **Generate the service certificates** on each API host (README §6.6) and set
   `Okta:Service:SigningCertificateThumbprint`. Leaving it blank selects the development
   assertion factory, which **refuses to run against anything but a loopback endpoint** —
   so it cannot silently weaken a real deployment.

4. **Run manual test cases 3, 4, 11 and 12** from README §15.5. Case 4 (launch AppB after
   closing every browser window) is the one that catches the persistent-cookie setting.

---

## About the registry

**The loopback redirect requires no registry writes.** This is worth stating plainly
because it is a common assumption.

`HttpListener` binds a high port on `127.0.0.1` as the interactive user. On Windows that
needs no URL ACL, no elevation, and no registration anywhere. README §4.3 chose loopback
over a custom URI scheme (`appa://`) precisely to avoid registry writes — and, more
importantly, because a custom scheme is a **machine-global namespace**: any other installed
application can register the same `appa://` and silently hijack your OAuth callback, with
no way for you to detect or prevent it.

**What Velopack does set up** (`build/publish.ps1`):

| | |
|---|---|
| Install location | `%LOCALAPPDATA%\Corp.AppA` — per-user, **no elevation** |
| Start Menu shortcut | Yes |
| Add/Remove Programs | `HKCU\...\Uninstall` — the only registry it touches, ordinary per-user install bookkeeping, unrelated to OAuth |
| Updates and rollback | Via `VelopackApp.Build().Run()`, the first line of `App.OnStartup` |

`VelopackApp.Build().Run()` must stay the first statement in `OnStartup`: on the first run
after an install or update it performs the hook and exits the process, so anything above it
would execute during installation.

```powershell
./build/publish.ps1 -App AppA -Version 1.0.0
# -> artifacts/AppA/Corp.AppA-win-Setup.exe
```

`build/register-uri-scheme.ps1` is included but **unused**. It is there for two legitimate
cases — you want deep links as a product feature, or your environment blocks loopback
binds — and it documents the trade-off rather than pretending the choice does not exist.
It writes to `HKCU`, so it needs no elevation either.

---

## Enabling Telerik

The shell talks to `IUserInteraction`, which has two implementations. `WpfUserInteraction`
(plain WPF) is used today; `TelerikUserInteraction` is compiled only under the `TELERIK`
symbol. Nothing outside `Corp.Identity.Wpf` references either, so switching is a one-line
registration change.

Once your licensed Telerik feed is configured:

1. Add the Telerik packages to `AppA`, `AppB` and `Corp.Identity.Wpf`.
2. Build with `-p:UseTelerik=true`, or set `<UseTelerik>true</UseTelerik>` in
   `Directory.Build.props`.
3. In `App.xaml.cs`, swap the factory to `new TelerikUserInteraction(() => ShellViewModel.Instance)`.
4. Replace the busy overlay in `ShellWindow.xaml` with a `RadBusyIndicator` wrapping the
   region (README §8.12).

The theme is set in `OnStartup` before any window is created, already guarded by `#if TELERIK`.

---

## Remaining gaps

Honest list. Everything else previously listed here is now closed.

| Gap | Why it is still open |
|---|---|
| **Never run against a live Okta tenant** | The protocol is exercised end to end against DevIdp, and Terraform provisions the tenant — but DevIdp is not Okta. Expect to hit real-tenant specifics: policy evaluation order, assignment gates, the multi-audience EA feature if you choose Variant A, and TLS interception on the way out (README §13.4). |
| **`X509ClientAssertionFactory` never used against Okta** | Its output is now fully unit-tested — audience, algorithm, signature, `jti`, lifetime — but no Okta endpoint has ever accepted one. The certificate ACL path (README §13.3) is likewise untested on a real IIS host. |
| **Terraform not applied** | Written against provider `~> 4.9` and never run. Attribute names drift across provider majors; expect to fix a few on first `plan`. Trusted servers and the Token Exchange grant are deliberately left as manual steps. |
| **No DPoP** | README §12.4 treats it as a planned phase two with a defined trigger, not a gap in this build. Token acquisition sits behind `IAuthenticationService`, so adding it touches one class per side. |
| **No back-channel logout** | Both APIs are stateless, so there is no server-side session to invalidate (README §11.3). It becomes necessary only if that changes. |
| **Velopack packaging unexercised** | `build/publish.ps1` is written but has not been run; `vpk` is not installed on this machine. |
