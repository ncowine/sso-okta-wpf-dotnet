using System.Text.Json;
using Corp.Identity.Shell;
using Prism.Commands;
using Prism.Mvvm;

namespace AppA.Views;

/// <summary>
/// Requires <c>apia.read</c> to open. UX only — ApiA enforces the same rule server-side,
/// which is the check that actually matters (README §8.13).
/// </summary>
[RequiresScope("apia.read")]
public sealed class HomeViewModel : BindableBase
{
    private const string SampleOrderId = "22222222-2222-2222-2222-222222222222";

    private readonly IApiClient _api;
    private readonly IUserInteraction _interaction;

    private string _output = "Press a button to make a call.";

    public HomeViewModel(IApiClient api, IUserInteraction interaction)
    {
        _api = api;
        _interaction = interaction;

        WhoAmICommand = new DelegateCommand(async () => await CallAsync("orders/whoami"));
        ListOrdersCommand = new DelegateCommand(async () => await CallAsync("orders"));
        BillingCommand = new DelegateCommand(async () => await CallAsync($"orders/{SampleOrderId}/billing"));
        ReconcileCommand = new DelegateCommand(async () => await CallAsync("orders/reconcile"));
    }

    public string Output { get => _output; private set => SetProperty(ref _output, value); }

    public DelegateCommand WhoAmICommand { get; }
    public DelegateCommand ListOrdersCommand { get; }
    public DelegateCommand BillingCommand { get; }
    public DelegateCommand ReconcileCommand { get; }

    private async Task CallAsync(string path)
    {
        using (_interaction.ShowBusy($"GET {path}…"))
        {
            try
            {
                var body = await _api.GetAsync(path);
                Output = $"GET {path}\n{new string('─', 60)}\n{Prettify(body)}";
            }
            catch (Exception ex)
            {
                // Never surface a raw token or an Okta error body to the user (README §D.6).
                Output = $"GET {path}\n{new string('─', 60)}\n{ex.GetType().Name}: {ex.Message}";
            }
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
