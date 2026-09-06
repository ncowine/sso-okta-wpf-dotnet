# Common.Authentication

Sign-in for a WPF desktop application, in one library. Your view models depend on
`IAuthenticationService` and never see a token.

Works with **either** redirect style — a private-use scheme like `myapp://auth/callback`, or
a loopback address like `http://127.0.0.1:8765/callback`. You configure one; the library
picks the right machinery.

---

## Wiring it up

### 1. Configuration

```jsonc
{
  "Authentication": {
    "Authority":   "https://dev-12345678.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9",
    "ClientId":    "0oa1a2b3c4d5e6f7g8h9",
    "RedirectUri": "myapp://auth/callback",
    "Scopes":      [ "openid", "profile", "email", "offline_access" ],

    "Resources": {
      "Orders": {
        "Scopes":      [ "orders.read", "orders.write" ],
        "BaseAddress": "https://orders.corp.example/"
      }
    }
  }
}
```

`offline_access` is what earns you a refresh token. Without it the user is asked to sign in
again the moment the first access token expires.

### 2. `App.xaml.cs`

Two things. The first must be the very first line, and only applies to a private-use scheme.

```csharp
public partial class App : Application
{
    private IHost _host = null!;

    protected override async void OnStartup(StartupEventArgs e)
    {
        // Windows delivers a myapp:// callback by starting a SECOND copy of this
        // executable. If that is why we are here, hand the URI to the copy that is
        // already running and stop — it is the one waiting for it.
        //
        // Single-instance behaviour comes free, which you want anyway: two copies would
        // otherwise fight over one token store.
        if (PrivateUriSchemeActivation.ForwardToRunningInstance(e.Args, "myapp"))
        {
            Shutdown();
            return;
        }

        base.OnStartup(e);

        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json")
            .Build();

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddCommonAuthentication(configuration);   // <- the whole thing

                services.AddSingleton<ShellViewModel>();
                services.AddSingleton<MainWindow>();
            })
            .Build();

        MainWindow = _host.Services.GetRequiredService<MainWindow>();
        MainWindow.Show();

        await _host.Services.GetRequiredService<ShellViewModel>().InitialiseAsync();
    }
}
```

If you use a loopback redirect instead, drop the `ForwardToRunningInstance` block entirely.
Nothing else changes.

### 3. A view model

```csharp
public sealed class ShellViewModel : ObservableObject
{
    private readonly IAuthenticationService _auth;
    private readonly IHttpClientFactory _httpClients;

    public ShellViewModel(IAuthenticationService auth, IHttpClientFactory httpClients)
    {
        _auth = auth;
        _httpClients = httpClients;

        SignInCommand  = new AsyncRelayCommand(SignInAsync, () => !IsSignedIn);
        SignOutCommand = new AsyncRelayCommand(SignOutAsync, () => IsSignedIn);

        // The service raises this on a background thread, so marshal before touching
        // anything bindable.
        _auth.StateChanged += (_, e) => Application.Current.Dispatcher.Invoke(() =>
        {
            IsSignedIn = e.IsSignedIn;
            SignedInAs = e.User?.FindFirst("preferred_username")?.Value ?? "Not signed in";

            // The one case worth telling the user about: they did not ask for this.
            if (e.Reason == AuthenticationChangeReason.SessionExpired)
                Status = "Your session ended. Please sign in again.";
        });
    }

    private bool _isSignedIn;
    public bool IsSignedIn { get => _isSignedIn; private set => SetProperty(ref _isSignedIn, value); }

    private string _signedInAs = "Not signed in";
    public string SignedInAs { get => _signedInAs; private set => SetProperty(ref _signedInAs, value); }

    private string _status = "";
    public string Status { get => _status; private set => SetProperty(ref _status, value); }

    public IAsyncRelayCommand SignInCommand { get; }
    public IAsyncRelayCommand SignOutCommand { get; }

    /// <summary>Call once after the window is up.</summary>
    public async Task InitialiseAsync()
    {
        // Silent. Uses the stored refresh token if there is one.
        var restored = await _auth.RestoreSessionAsync();

        // Still silent if the user's browser already has a session with the provider —
        // which it will if they signed in to the web dashboard this morning.
        if (!restored.Succeeded) await SignInAsync();
    }

    private async Task SignInAsync()
    {
        var result = await _auth.SignInAsync();
        Status = result.ToDisplayMessage();
    }

    private async Task SignOutAsync()
    {
        // Application: forget our tokens, leave the browser session alone.
        // Everywhere:  also end the provider session — signs them out of every app.
        //              Ask first; people report it as a bug otherwise.
        await _auth.SignOutAsync(SignOutScope.Application);
    }

    /// <summary>Calling an API. No token in sight — the handler attaches it.</summary>
    public async Task<Order[]> LoadOrdersAsync()
    {
        var http = _httpClients.CreateClient("Orders");
        return await http.GetFromJsonAsync<Order[]>("orders") ?? [];
    }
}
```

That is the whole integration. `"Orders"` is the key from `Resources` — base address, bearer
token, refresh, and a single retry on 401 are all attached for you.

---

## Registering `myapp://` with Windows

By default the library registers the scheme on first run, under `HKEY_CURRENT_USER`. No
elevation, no effect on other users, and it checks before writing so a normal launch does no
registry work at all.

If your installer does the registration instead — tidier, and preferable — turn it off:

```jsonc
"RegisterUriScheme": false
```

The registration is three values:

```
HKCU\Software\Classes\myapp
    (default)      = "URL:myapp"
    "URL Protocol" = ""
    shell\open\command\(default) = "C:\Path\To\YourApp.exe" "%1"
```

---

## Two things worth knowing

**A private-use scheme is a machine-wide namespace.** Any other installed application can
register `myapp://` too, and on Windows the last writer wins. This is why PKCE and `state`
are always on and not configurable: an intercepted authorization code is useless without the
verifier, which never leaves this process.
[RFC 8252 §7.1](https://datatracker.ietf.org/doc/html/rfc8252#section-7.1) describes the
limitation; §7.3 covers the loopback alternative, which cannot be claimed by anyone else and
is what the RFC prefers. If you get to choose, choose loopback. If your provider is already
configured for a scheme, this library handles it properly.

**The browser opening is the feature, not the bug.** It is deliberately the user's real
browser and never an embedded control. That browser holds the provider's session cookie, so
after the first sign-in of the day everything else is silent — which is exactly the
behaviour you get from tiles on a web dashboard. An embedded WebView has its own empty
cookie jar and will prompt every time, in every application, forever.

---

## What's in here

| | |
|---|---|
| `IAuthenticationService.cs` | The only type your application should reference |
| `AuthenticationOptions.cs` | Configuration, with validation that fails loudly at startup |
| `AuthenticationService.cs` | Session state, refresh, sign-out |
| `Protocol/` | PKCE, the OIDC calls, ID token validation |
| `Callback/` | Private-use scheme (registry, single instance, named pipe) and loopback |
| `Storage/` | DPAPI-encrypted refresh token, in-memory access token cache |
| `Http/` | The handler that attaches tokens and retries once on 401 |

Every dependency is published by Microsoft. There is no third-party package to get approved.
