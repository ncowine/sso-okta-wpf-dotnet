# Demo solution

The runnable companion to [README.md](README.md). The README is the specification; this
is the implementation, and every non-obvious decision in the code points back to a README
section by number.

> **Status:** builds clean, 22/22 tests pass. It will not sign in until you fill in your
> Okta tenant values — see [Configure Okta](#3-configure-okta).

---

## Layout

```
SSO.sln
├── src/
│   ├── Corp.Identity.Client/     Shared desktop auth: PKCE, loopback, DPAPI, refresh
│   ├── Corp.Identity.Shell/      Prism + shell abstractions (plain WPF / Telerik)
│   ├── Corp.Api.Security/        Shared API auth: validation + §7 delegation patterns
│   ├── AppA/  AppB/              WPF clients (.NET 8, Prism 8, Velopack)
│   └── ApiA/  ApiB/              ASP.NET Core APIs that call each other
├── tests/
│   └── Corp.Api.Security.Tests/  Negative token tests + CI configuration guards
└── build/
    ├── publish.ps1               Velopack packaging
    └── register-uri-scheme.ps1   OPTIONAL, not used — see "About the registry"
```

Both WPF apps share one authentication library and differ only in configuration. Both
APIs share one security library. Nothing is duplicated — divergent copies of auth code
become a security bug in whichever copy gets less attention (README §8.1).

---

## 1. Prerequisites

| | |
|---|---|
| .NET 8 SDK | Present. `global.json` pins `8.0.421`. |
| Okta org | Free Integrator plan is enough — it includes API Access Management (README §5.1). |
| Velopack CLI | Only for packaging: `dotnet tool install -g vpk` |
| Telerik | **Not required.** See [Enabling Telerik](#enabling-telerik). |

## 2. Build and test

```bash
dotnet build SSO.sln
dotnet test tests/Corp.Api.Security.Tests
```

Both should be clean before you touch any configuration.

## 3. Configure Okta

Work through **README §6**, filling in **README Appendix B** as you go. Then transfer the
values into the four `appsettings.json` files — every placeholder is spelled `REPLACE-ME`,
and the applications refuse to start with a clear message if you miss one.

| File | Needs |
|---|---|
| `src/AppA/appsettings.json` | Okta domain, AppA client ID, ApiA authorization server ID |
| `src/AppB/appsettings.json` | Okta domain, AppB client ID, ApiB authorization server ID |
| `src/ApiA/appsettings.json` | ApiA issuer + audience; ApiA service client ID + cert thumbprint; ApiB downstream |
| `src/ApiB/appsettings.json` | ApiB issuer + audience; ApiB service client ID + cert thumbprint; ApiA downstream |

**Redirect URIs.** Register all three loopback ports per app, sign-in *and* sign-out:

```
AppA   http://127.0.0.1:8765/callback   :8766   :8767
       http://127.0.0.1:8765/signout-callback   :8766   :8767
AppB   http://127.0.0.1:8865/callback   :8866   :8867
       http://127.0.0.1:8865/signout-callback   :8866   :8867
```

The client probes its ports in order and fails over when one is bound, so two instances
of the same app can both sign in (README §4.3, §8.5). Every port it might use must be
registered, or Okta rejects the authorize request.

> Do not write code until **Token Preview** (README §6.8) returns a clean token. It is the
> same policy engine your app will hit, and it diagnoses in thirty seconds what otherwise
> takes a day.

## 4. Run it

```bash
dotnet run --project src/ApiA     # https://localhost:7201
dotnet run --project src/ApiB     # https://localhost:7202
dotnet run --project src/AppA
```

`AppA` tries a silent restore, falls back to an interactive browser sign-in, then lands on
the token explorer.

---

## What to actually look at

The demo exists to make README §7 concrete. Four buttons, and the interesting part is
comparing what each one produces.

| Button | Endpoint | What it shows |
|---|---|---|
| **Who am I? (ApiA)** | `GET /orders/whoami` | How ApiA sees your token: `sub`, `uid`, `cid`, `scp`, `groups` |
| **List orders** | `GET /orders` | Scope check *plus* per-record group filtering — scopes are necessary, never sufficient (README §9.3) |
| **ApiA → ApiB (on behalf of me)** | `GET /orders/{id}/billing` | The delegated call, using whichever §7 pattern is configured |
| **ApiA → ApiB (service identity)** | `GET /orders/reconcile` | The same hop as a *service*, with no user at all |

### The exercise that teaches the most

1. Click **Who am I? (ApiA)**. Note `subject` and `callingClientId`.
2. Click **ApiA → ApiB (on behalf of me)**. ApiB reports the **same subject**, but
   `callingClientId` is now ApiA's *service* client. The user survived the hop; the acting
   service is recorded. That is README §7.1 working.
3. Click **ApiA → ApiB (service identity)**. Now `isServicePrincipal` is `true` and there
   is **no subject at all**. ApiB is authorising the *service*, and your permissions were
   never consulted — which is exactly why §7.2 says never to use this shape for a
   user-initiated request.
4. Open `src/ApiA/appsettings.json`, set `Delegation:Pattern` to `ClientRelayed`, restart
   ApiA, and repeat step 2. It fails, and the error tells you why: Pattern 3 requires the
   desktop client to acquire a *second* token for `api://apib` and relay it
   (README §7.3, §8.9). That failure is the point — it shows precisely what Pattern 1 was
   doing for you.

### Switching delegation pattern

```jsonc
// src/ApiA/appsettings.json
"Delegation": { "Pattern": "OnBehalfOf" }   // or "ClientRelayed"
```

Pattern 2 (client credentials) is not a setting — it is a *separate named client*, chosen
per call site. `OrdersController.Billing` uses the user client; `OrdersController.Reconcile`
uses the background one. Two distinct clients, deliberately, so the most damaging mistake
in §7 is visible in review rather than buried in a handler (README §9.5).

---

## About the registry

**The loopback redirect requires no registry writes.** This is worth stating plainly
because it is a common assumption, and it was the premise of the original request for
this demo.

`HttpListener` binds a high port on `127.0.0.1` as the interactive user. On Windows that
needs no URL ACL, no elevation, and no registration anywhere. README §4.3 chose loopback
over a custom URI scheme (`appa://`) precisely to avoid registry writes — and, more
importantly, because a custom scheme is a **machine-global namespace**: any other
installed application can register the same `appa://` and silently hijack your OAuth
callback, with no way for you to detect or prevent it.

**What Velopack does set up** (`build/publish.ps1`):

| | |
|---|---|
| Install location | `%LOCALAPPDATA%\Corp.AppA` — per-user, **no elevation** |
| Start Menu shortcut | Yes |
| Add/Remove Programs | `HKCU\...\Uninstall` — the only registry it touches, and it is ordinary per-user install bookkeeping, unrelated to OAuth |
| Updates and rollback | Via `VelopackApp.Build().Run()`, the first line of `App.OnStartup` |

`VelopackApp.Build().Run()` must stay the first statement in `OnStartup`: on the first run
after an install or update it performs the hook and exits the process, so anything above
it would execute during installation.

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
symbol. Nothing outside `Corp.Identity.Shell` references either, so switching is a
one-line registration change.

Once your licensed Telerik feed is configured:

1. Add the Telerik packages to `AppA`, `AppB` and `Corp.Identity.Shell`.
2. Build with `-p:UseTelerik=true`, or set `<UseTelerik>true</UseTelerik>` in
   `Directory.Build.props`.
3. In `App.xaml.cs`, swap the factory to `new TelerikUserInteraction(ShellViewModel.Instance)`.
4. Replace the busy overlay in `ShellWindow.xaml` with a `RadBusyIndicator` wrapping the
   region (README §8.12).

The theme is set in `OnStartup`, before any window is created, already guarded by
`#if TELERIK`.

---

## Known gaps

Honest list of what is scaffolded but not finished.

| Gap | Notes |
|---|---|
| **No live Okta tenant** | Every value is a placeholder. Nothing has been run end to end against Okta. |
| **`X509ClientAssertionFactory` untested** | Needs a real certificate in `LocalMachine\My`. The code follows README §7.1 but has never authenticated to Okta. |
| **`ApiB → ApiA` direction unused** | Configured symmetrically, but no ApiB endpoint calls back into ApiA yet. The delegation-depth guard (README §7.7) is registered and unit-testable but not exercised by a real cycle. |
| **Pattern 3 client half missing** | `ClientRelayedTokenHandler` forwards the second token, but `AppA` does not yet acquire one (README §8.9). Selecting `ClientRelayed` fails with an explanatory error — deliberately, see the exercise above. |
| **No Prism modules** | Views are registered directly. `ConfigureModuleCatalog` (README §8.11) is not used at this size. |
| **`AppB` is a mirror of `AppA`** | Same shape against ApiB. Enough to demonstrate cross-app SSO (README §10.1); not a distinct application. |
| **No integration tests against Okta** | README §15.4 describes them; they need a tenant. |

## Next steps

1. Create the Okta tenant and work README §6 → Appendix B.
2. Run manual test cases 3 and 4 from README §15.5 — launch `AppB` after `AppA` and
   confirm no prompt. That is the SSO moment, and case 4 (after closing all browser
   windows) is the one that catches the persistent-cookie setting in README §10.1.
3. Run the §7.6 spike to confirm Token Exchange works on your org, then commit to a
   pattern.
4. Fill the gaps above that matter to you.
