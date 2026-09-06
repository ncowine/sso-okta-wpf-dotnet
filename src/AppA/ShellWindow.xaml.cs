using System.Windows;

namespace AppA;

/// <summary>The one window. Its DataContext is injected, so the XAML binds to real state.</summary>
public partial class ShellWindow : Window
{
    public ShellWindow(ShellViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
