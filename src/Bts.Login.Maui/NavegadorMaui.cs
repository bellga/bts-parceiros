using Bts.Login.Cliente;

namespace Bts.Login.Maui;

/// <summary>
/// Navegador do sistema no MAUI. Android e iOS: <see cref="WebAuthenticator"/> (aba segura do navegador, volta pelo
/// esquema do app). Windows: retorno local em 127.0.0.1 (o WebAuthenticator não funciona no Windows).
/// </summary>
public sealed class NavegadorMaui : INavegadorBts
{
#if WINDOWS
    private readonly NavegadorRetornoLocal _local = new(u => Launcher.Default.OpenAsync(u));

    public Task<Uri> PrepararRetornoAsync(Uri cadastrado, CancellationToken ct) => _local.PrepararRetornoAsync(cadastrado, ct);

    public Task<Uri> AbrirAsync(Uri autorizar, Uri retorno, CancellationToken ct) => _local.AbrirAsync(autorizar, retorno, ct);
#else
    public Task<Uri> PrepararRetornoAsync(Uri cadastrado, CancellationToken ct) => Task.FromResult(cadastrado);

    public async Task<Uri> AbrirAsync(Uri autorizar, Uri retorno, CancellationToken ct)
    {
        var resultado = await MainThread.InvokeOnMainThreadAsync(() =>
            WebAuthenticator.Default.AuthenticateAsync(new WebAuthenticatorOptions
            {
                Url = autorizar,
                CallbackUrl = retorno,
                PrefersEphemeralWebBrowserSession = false // mantém a sessão da BTS: quem já entrou não digita a senha de novo
            }));
        ct.ThrowIfCancellationRequested();
        // O WebAuthenticator devolve os parâmetros já separados: remonta o endereço de volta
        var consulta = string.Join('&', resultado.Properties.Select(p =>
            $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value ?? "")}"));
        return new Uri($"{retorno}?{consulta}");
    }
#endif
}

/// <summary>Atalho para criar o cliente no MAUI.</summary>
public static class BtsLoginMaui
{
    /// <summary>
    /// Cria o cliente com o navegador certo para a plataforma. Use <paramref name="retornoCelular"/> no Android/iOS
    /// (esquema do app) e <paramref name="retornoComputador"/> no Windows (<c>http://127.0.0.1/bts</c>).
    /// </summary>
    public static BtsCliente Criar(string clientId, string retornoCelular, string retornoComputador = "http://127.0.0.1/bts",
        Action<BtsClienteOptions>? configurar = null, HttpClient? http = null)
    {
        var o = new BtsClienteOptions
        {
            ClientId = clientId,
            RetornoUri = DeviceInfo.Current.Platform == DevicePlatform.WinUI ? retornoComputador : retornoCelular
        };
        configurar?.Invoke(o);
        return new BtsCliente(o, new NavegadorMaui(), http);
    }
}
