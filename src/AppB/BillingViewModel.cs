using System.Net.Http;
using System.Text.Json;
using Prism.Mvvm;

namespace AppB;

/// <summary>
/// Calls ApiB and shows what came back.
/// </summary>
/// <remarks>
/// The point of this class is how little is in it. There is no token here, no expiry
/// check, no refresh, no Authorization header. The named HttpClient was registered by
/// <c>AddCommonAuthentication</c> and arrives with all of that attached.
/// </remarks>
public sealed class BillingViewModel : BindableBase
{
    /// <summary>Keys from Authentication:Resources in appsettings.json.</summary>
    private const string ApiB = "ApiB";
    private const string ApiA = "ApiA";

    private const string SampleInvoiceId = "22222222-2222-2222-2222-222222222222";

    private readonly IHttpClientFactory _httpClients;

    private string _output =
        "AppB - Billing" + Environment.NewLine + Environment.NewLine +
        "If you were not prompted to sign in, the browser session from AppA was reused. " +
        "AppB still received its own, separate tokens.";
    private bool _isBusy;

    public BillingViewModel(IHttpClientFactory httpClients)
    {
        _httpClients = httpClients;

        WhoAmICommand = Call(ApiB, "invoices/whoami");
        InvoiceCommand = Call(ApiB, $"invoices/{SampleInvoiceId}");
        OrderContextCommand = Call(ApiB, $"invoices/{SampleInvoiceId}/order-context");
        CycleCommand = Call(ApiB, "invoices/cycle-demo");

        // The direct call. ApiA has its own authorization server; the token for it is
        // acquired on first use with a silent authorize, using the browser session the
        // ApiB sign-in already established. Contrast with "ApiA → ApiB", which is
        // delegation — ApiB minting a token for the hop.
        WhoAmIViaApiADirectCommand = Call(ApiA, "orders/whoami");
    }

    public string Output { get => _output; private set => SetProperty(ref _output, value); }
    public bool IsBusy { get => _isBusy; private set => SetProperty(ref _isBusy, value); }

    public AsyncCommand WhoAmICommand { get; }
    public AsyncCommand InvoiceCommand { get; }
    public AsyncCommand OrderContextCommand { get; }
    public AsyncCommand CycleCommand { get; }
    public AsyncCommand WhoAmIViaApiADirectCommand { get; }

    private AsyncCommand Call(string api, string path) => new(() => GetAsync(api, path));

    private async Task GetAsync(string api, string path)
    {
        IsBusy = true;

        try
        {
            var http = _httpClients.CreateClient(api);

            using var response = await http.GetAsync(path);
            var body = await response.Content.ReadAsStringAsync();

            Output = $"GET {api}/{path}{Environment.NewLine}{new string('-', 60)}{Environment.NewLine}" +
                     (response.IsSuccessStatusCode
                         ? Prettify(body)
                         : $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}{Environment.NewLine}{Environment.NewLine}{body}");
        }
        catch (Exception ex)
        {
            // Never put a raw token or a provider error body in front of a user. The type
            // and message are enough to act on, and safe to show.
            Output = $"GET {api}/{path}{Environment.NewLine}{new string('-', 60)}{Environment.NewLine}" +
                     $"{ex.GetType().Name}: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
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
