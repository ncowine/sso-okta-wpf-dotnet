using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace AppA;

/// <summary>
/// Calls ApiA and shows what came back.
/// </summary>
/// <remarks>
/// The point of this class is how little is in it. There is no token here, no expiry
/// check, no refresh, no Authorization header. The named HttpClient was registered by
/// <c>AddCommonAuthentication</c> and arrives with all of that attached.
/// </remarks>
public sealed class OrdersViewModel : ObservableObject
{
    /// <summary>The key from Authentication:Resources in appsettings.json.</summary>
    private const string Api = "ApiA";

    private const string SampleOrderId = "22222222-2222-2222-2222-222222222222";

    private readonly IHttpClientFactory _httpClients;

    private string _output = "Press a button to call the API.";
    private bool _isBusy;

    public OrdersViewModel(IHttpClientFactory httpClients)
    {
        _httpClients = httpClients;

        WhoAmICommand   = Call("orders/whoami");
        ListOrdersCommand = Call("orders");
        BillingCommand  = Call($"orders/{SampleOrderId}/billing");
        ReconcileCommand = Call("orders/reconcile");
    }

    public string Output { get => _output; private set => SetProperty(ref _output, value); }
    public bool IsBusy { get => _isBusy; private set => SetProperty(ref _isBusy, value); }

    public AsyncCommand WhoAmICommand { get; }
    public AsyncCommand ListOrdersCommand { get; }
    public AsyncCommand BillingCommand { get; }
    public AsyncCommand ReconcileCommand { get; }

    private AsyncCommand Call(string path) => new(() => GetAsync(path));

    private async Task GetAsync(string path)
    {
        IsBusy = true;

        try
        {
            var http = _httpClients.CreateClient(Api);

            using var response = await http.GetAsync(path);
            var body = await response.Content.ReadAsStringAsync();

            Output = $"GET {path}{Environment.NewLine}{new string('-', 60)}{Environment.NewLine}" +
                     (response.IsSuccessStatusCode
                         ? Prettify(body)
                         : $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}{Environment.NewLine}{Environment.NewLine}{body}");
        }
        catch (Exception ex)
        {
            // Never put a raw token or a provider error body in front of a user. The type
            // and message are enough to act on, and safe to show.
            Output = $"GET {path}{Environment.NewLine}{new string('-', 60)}{Environment.NewLine}" +
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
