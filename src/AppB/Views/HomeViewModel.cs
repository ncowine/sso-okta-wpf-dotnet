using System.Text.Json;
using Corp.Identity.Prism;
using Corp.Identity.Wpf;
using Prism.Commands;
using Prism.Mvvm;

namespace AppB.Views;

/// <summary>
/// AppB's billing surface. Deliberately different from AppA, not a mirror.
/// </summary>
/// <remarks>
/// <para>Its purpose in the demo is threefold:</para>
/// <list type="number">
/// <item>Prove cross-app SSO — launching AppB after AppA does not prompt (README §10.1).</item>
/// <item>Show the RETURN direction of the bidirectional relationship: ApiB calling back
/// into ApiA on the user's behalf (README §5.7 — trust is directional).</item>
/// <item>Show the delegation depth guard actually tripping (README §7.7).</item>
/// </list>
/// </remarks>
[RequiresScope("apib.read")]
public sealed class HomeViewModel : BindableBase
{
    private const string SampleInvoiceId = "22222222-2222-2222-2222-222222222222";

    private readonly IApiClient _api;
    private readonly IUserInteraction _interaction;

    private string _output =
        "AppB — Billing\n\n" +
        "If you launched AppA first and were not prompted to sign in here, you have just\n" +
        "watched cross-app SSO work: the Okta session cookie in your system browser was\n" +
        "reused, and AppB received its own separate tokens (README §10.1).";

    public HomeViewModel(IApiClient api, IUserInteraction interaction)
    {
        _api = api;
        _interaction = interaction;

        WhoAmICommand = new DelegateCommand(async () => await CallAsync("invoices/whoami"));
        InvoiceCommand = new DelegateCommand(async () => await CallAsync($"invoices/{SampleInvoiceId}"));
        OrderContextCommand = new DelegateCommand(
            async () => await CallAsync($"invoices/{SampleInvoiceId}/order-context"));
        CycleCommand = new DelegateCommand(async () => await CallAsync("invoices/cycle-demo"));
        SummaryCommand = new DelegateCommand(async () => await CallAsync("invoices/summary"));
    }

    public string Output { get => _output; private set => SetProperty(ref _output, value); }

    public DelegateCommand WhoAmICommand { get; }
    public DelegateCommand InvoiceCommand { get; }
    public DelegateCommand OrderContextCommand { get; }
    public DelegateCommand CycleCommand { get; }
    public DelegateCommand SummaryCommand { get; }

    private async Task CallAsync(string path)
    {
        using (_interaction.ShowBusy($"GET {path}…"))
        {
            try
            {
                var body = await _api.GetAsync(path);
                Output = $"GET {path}\n{new string('─', 64)}\n{Prettify(body)}{Explain(path, body)}";
            }
            catch (Exception ex)
            {
                // Never surface a raw token or an Okta error body to the user (README §D.6).
                Output = $"GET {path}\n{new string('─', 64)}\n{ex.GetType().Name}: {ex.Message}";
            }
        }
    }

    /// <summary>A short note on what the response actually demonstrates.</summary>
    private static string Explain(string path, string body)
    {
        if (path.EndsWith("order-context", StringComparison.Ordinal))
        {
            return "\n\n── What this shows ──\n" +
                   "ApiB called back into ApiA on your behalf. Note 'depthOnArrival' and the\n" +
                   "subject ApiA saw. This direction needs its own trusted-server entry in\n" +
                   "Okta — trust is directional (README §5.7).";
        }

        if (path.EndsWith("cycle-demo", StringComparison.Ordinal))
        {
            return "\n\n── What this shows ──\n" +
                   "A deliberate ApiB → ApiA → ApiB … cycle. Every hop is individually valid;\n" +
                   "nothing in OAuth stops it. Expect HTTP 508 once the depth guard refuses.\n" +
                   "Unguarded, this can exhaust the org-wide Okta /token rate limit and block\n" +
                   "sign-in for unrelated applications (README §7.7).";
        }

        if (body.Contains("\"status\": 403", StringComparison.Ordinal) ||
            body.StartsWith("HTTP 403", StringComparison.Ordinal))
        {
            return "\n\n── What this shows ──\n" +
                   "ApiB refused, using the groups in the token IT received rather than taking\n" +
                   "any caller's word for it. Sign in as alice@contoso.com (App-Finance) to see\n" +
                   "this succeed, or bob@contoso.com to see it denied (README §7.1).";
        }

        return string.Empty;
    }

    private static string Prettify(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            return JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException)
        {
            return body;
        }
    }
}
