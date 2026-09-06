# Running the demo

The runnable companion to [GUIDE.md](GUIDE.md). No Okta tenant required —
`tools/DevIdp` is a local authorization server that speaks the same protocol.

---

## Layout

```
SSO.sln
├── src/
│   ├── Common.Authentication/    Desktop sign-in. PKCE, callback handling, DPAPI storage,
│   │                             token attachment. Microsoft packages only.
│   ├── Common.Api.Security/      API-side token validation and service-to-service delegation.
│   ├── AppA/  AppB/              WPF clients. Plain WPF and MVVM — no framework.
│   └── ApiA/  ApiB/              ASP.NET Core APIs that call each other, both directions.
├── tools/
│   └── DevIdp/                   Local stand-in for Okta. Development only.
├── tests/
│   ├── Common.Authentication.Tests/  PKCE vectors, ID token rejection, config guards
│   └── Common.Api.Security.Tests/    Negative token tests, CI guards, end-to-end delegation
└── infra/okta/                   Terraform for a real tenant
```

**Nine projects, no third-party packages.** Every dependency is published by Microsoft,
so there is nothing to get approved before any of this can ship.

---

## Run it

```bash
dotnet run --project tools/DevIdp     # https://localhost:7100
dotnet run --project src/ApiA         # https://localhost:7201
dotnet run --project src/ApiB         # https://localhost:7202
dotnet run --project src/AppA
```

Order matters: the APIs fetch signing keys from DevIdp at startup and fail fast if it is
unreachable, so a misconfiguration surfaces immediately rather than on the first request.

If the browser complains about the certificate:

```bash
dotnet dev-certs https --trust
```

Sign in as **alice@contoso.com** (App-Finance, App-Warehouse) or **bob@contoso.com**
(App-Warehouse only). The difference between them is what makes authorization visible.

### The browser will ask permission to open the app

The demo apps are configured with a **private-use scheme** — `appa://auth/callback` — because
that is what most existing Okta app registrations use. The first time a sign-in completes,
Windows asks whether to open AppA. That prompt is Windows, not the application.

The scheme is registered under `HKEY_CURRENT_USER` on first run — no elevation, and it
affects only your account. To remove it afterwards:

```powershell
Remove-Item -Path HKCU:\Software\Classes\appa -Recurse
Remove-Item -Path HKCU:\Software\Classes\appb -Recurse
```

To use a loopback redirect instead, change one line in `appsettings.Development.json`:

```jsonc
"RedirectUri": "http://127.0.0.1:8765/callback"
```

Nothing else changes. `Common.Authentication` reads the shape of the URI and picks the right
machinery.

---

## What to look at

| Click | What it shows |
|---|---|
| **Who am I?** | How the API sees your token: subject, scopes, groups, calling client |
| **List orders** | A scope check *plus* per-record filtering by group. Alice and Bob see different rows. |
| **Call ApiB as me** | ApiA calls ApiB on your behalf. Same user, different audience, ApiA recorded as the acting service. |
| **Call ApiB as itself** | The same hop as a service, with no user at all. Note there is no subject. |

In AppB:

| Click | What it shows |
|---|---|
| **Who am I?** | AppB's own token, from its own authorization server |
| **Get invoice** | Requires App-Finance. Alice succeeds, Bob gets 403. |
| **Call ApiA from ApiB** | The return direction — trust between APIs is configured per direction |
| **Trip the cycle guard** | ApiB → ApiA → ApiB until the depth guard returns `508` |

### The two exercises worth doing

**Cross-application SSO.** With AppA running, launch AppB. You are not prompted. AppB got
its own separate tokens; the only thing shared was the browser session. That is the whole
mechanism, and it is why the sign-in happens in the real browser rather than an embedded
one.

**The downstream API does not trust the upstream one.** Sign out, sign in as **bob**, and
click *Call ApiB as me*. ApiA is happy to make the call; ApiB returns 403, because the
delegated token carries Bob's groups rather than ApiA's opinion of them.

---

## Watching it happen

A WPF app has no console, but redirecting stdout shows the whole flow:

```bash
dotnet run --project src/AppA > appa.log 2>&1
```

You will see the silent attempt, whether it succeeded, and the callback arriving. This is
the fastest way to understand the flow and the fastest way to debug it later.

---

## Tests

```bash
dotnet test
```

**86 tests.**

`Common.Authentication.Tests` (44) covers the RFC 7636 PKCE vector, seven ID-token rejection
cases, the configuration guards, the access-token cache's renewal margin, and the
single-instance gate — the last of these a regression suite for a defect that let a callback
launch a second copy of the application.

`Common.Api.Security.Tests` (42) is weighted towards what must be *rejected* — wrong audience,
foreign issuer, algorithm confusion, expired tokens — plus an end-to-end delegation chain that
runs all three hosts in-process.

---

## About DevIdp

⚠️ **Development only.** It authenticates nobody, checks no credentials, and signs with a
key generated at startup.

It reproduces Okta's *shapes*, because those are what break code: `scp` and `groups` as JSON
arrays, an access-token `sub` that differs from the ID-token `sub`, rotating refresh tokens
with replay detection, a session cookie so the second app signs in silently, and
`prompt=none` returning `login_required`.

---

## Going to a real tenant

`infra/okta/` has Terraform for the whole topology. Fill in the four `appsettings.json`
files from its outputs — every placeholder reads `REPLACE-ME`, and the applications refuse
to start with a clear message if you miss one.

Then run `terraform output manual_steps_remaining`, which lists the four things Terraform
cannot cover: trusted servers, the Token Exchange grant, the persistent session cookie
setting, and verifying with Token Preview. [GUIDE.md §8](GUIDE.md#8-standing-up-a-real-okta-tenant)
explains why each one matters.
