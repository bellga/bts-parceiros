using System.Windows.Input;
using Microsoft.Maui.Controls.Shapes;
using Path = Microsoft.Maui.Controls.Shapes.Path;

namespace Bts.Login.Maui;

public enum TemaBotaoBts { Escuro, Claro }
public enum TextoBotaoBts { Entrar, Continuar }

/// <summary>
/// Botão oficial "Entrar com BTS" (mesmas cores e medidas de https://bellga.tech/marca.html).
/// Não mude cores, texto nem proporções.
/// </summary>
public sealed class BotaoBts : ContentView
{
    private static readonly Color Marca = Color.FromArgb("#0f5c55");
    private static readonly Color MarcaHover = Color.FromArgb("#0c4b45");
    private static readonly Color Tinta = Color.FromArgb("#14201f");
    private static readonly Color Borda = Color.FromArgb("#c3cbc6");
    private const string Escudo = "M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z M9 12l2 2 4-4";

    public static readonly BindableProperty TemaProperty = BindableProperty.Create(nameof(Tema), typeof(TemaBotaoBts),
        typeof(BotaoBts), TemaBotaoBts.Escuro, propertyChanged: (b, _, _) => ((BotaoBts)b).Montar());
    public static readonly BindableProperty TextoProperty = BindableProperty.Create(nameof(Texto), typeof(TextoBotaoBts),
        typeof(BotaoBts), TextoBotaoBts.Entrar, propertyChanged: (b, _, _) => ((BotaoBts)b).Montar());
    public static readonly BindableProperty SoIconeProperty = BindableProperty.Create(nameof(SoIcone), typeof(bool),
        typeof(BotaoBts), false, propertyChanged: (b, _, _) => ((BotaoBts)b).Montar());
    public static readonly BindableProperty CommandProperty = BindableProperty.Create(nameof(Command), typeof(ICommand),
        typeof(BotaoBts));

    public TemaBotaoBts Tema { get => (TemaBotaoBts)GetValue(TemaProperty); set => SetValue(TemaProperty, value); }
    public TextoBotaoBts Texto { get => (TextoBotaoBts)GetValue(TextoProperty); set => SetValue(TextoProperty, value); }
    public bool SoIcone { get => (bool)GetValue(SoIconeProperty); set => SetValue(SoIconeProperty, value); }
    public ICommand? Command { get => (ICommand?)GetValue(CommandProperty); set => SetValue(CommandProperty, value); }

    /// <summary>Tocou no botão.</summary>
    public event EventHandler? Clicked;

    public string Rotulo => Texto == TextoBotaoBts.Continuar ? "Continuar com BTS" : "Entrar com BTS";

    public BotaoBts()
    {
        var toque = new TapGestureRecognizer();
        toque.Tapped += (_, _) => Tocar();
        GestureRecognizers.Add(toque);
        Montar();
    }

    private void Tocar()
    {
        if (!IsEnabled) return;
        Clicked?.Invoke(this, EventArgs.Empty);
        if (Command?.CanExecute(null) == true) Command.Execute(null);
    }

    private void Montar()
    {
        var escuro = Tema == TemaBotaoBts.Escuro;
        var fundo = escuro ? Marca : Colors.White;

        View icone;
        if (SoIcone && escuro)
            icone = EscudoView(26.4, Colors.White); // ícone sozinho escuro: escudo branco direto no fundo verde
        else
            icone = new Border
            {
                WidthRequest = 22,
                HeightRequest = 22,
                StrokeThickness = 0,
                StrokeShape = new RoundRectangle { CornerRadius = 5.5 },
                BackgroundColor = escuro ? Colors.White : Marca,
                Content = EscudoView(14.5, escuro ? Marca : Colors.White),
                VerticalOptions = LayoutOptions.Center
            };

        View conteudo = SoIcone
            ? icone
            : new HorizontalStackLayout
            {
                Spacing = 10,
                VerticalOptions = LayoutOptions.Center,
                Children =
                {
                    icone,
                    new Label
                    {
                        Text = Rotulo,
                        FontSize = 15,
                        FontAttributes = FontAttributes.None,
                        TextColor = escuro ? Colors.White : Tinta,
                        VerticalOptions = LayoutOptions.Center,
                        MaxLines = 1
                    }
                }
            };

        var caixa = new Border
        {
            HeightRequest = 40,
            MinimumHeightRequest = 40,
            WidthRequest = SoIcone ? 40 : -1,
            Padding = SoIcone ? new Thickness(0) : new Thickness(10, 0, 16, 0),
            BackgroundColor = fundo,
            Stroke = escuro ? fundo : Borda,
            StrokeThickness = escuro ? 0 : 1,
            StrokeShape = new RoundRectangle { CornerRadius = 8 },
            HorizontalOptions = LayoutOptions.Start,
            Content = new Grid { Children = { conteudo }, HorizontalOptions = SoIcone ? LayoutOptions.Center : LayoutOptions.Start }
        };
        if (SoIcone) conteudo.HorizontalOptions = LayoutOptions.Center;

        // Realce ao passar o mouse (Windows) e ao tocar
        var ponteiro = new PointerGestureRecognizer();
        ponteiro.PointerEntered += (_, _) => caixa.BackgroundColor = escuro ? MarcaHover : Color.FromArgb("#f3f5f2");
        ponteiro.PointerExited += (_, _) => caixa.BackgroundColor = fundo;
        caixa.GestureRecognizers.Add(ponteiro);

        Content = caixa;
        SemanticProperties.SetDescription(this, Rotulo);
        AutomationProperties.SetIsInAccessibleTree(this, true);
    }

    /// <summary>Escudo desenhado na grade 24 × 24 (como o SVG) e reduzido por escala: o traço diminui junto.</summary>
    private static View EscudoView(double tamanho, Color cor) => new Grid
    {
        WidthRequest = tamanho,
        HeightRequest = tamanho,
        HorizontalOptions = LayoutOptions.Center,
        VerticalOptions = LayoutOptions.Center,
        InputTransparent = true,
        Children =
        {
            new Path
            {
                Data = (Geometry)new PathGeometryConverter().ConvertFromInvariantString(Escudo)!,
                Stroke = cor,
                StrokeThickness = 2.4,
                StrokeLineCap = PenLineCap.Round,
                StrokeLineJoin = PenLineJoin.Round,
                Fill = Colors.Transparent,
                Aspect = Stretch.None,
                WidthRequest = 24,
                HeightRequest = 24,
                Scale = tamanho / 24,
                HorizontalOptions = LayoutOptions.Center,
                VerticalOptions = LayoutOptions.Center
            }
        }
    };
}
