using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Bts.Login.Cliente;

/// <summary>
/// Apps de computador (Windows, macOS, Linux): abre o navegador do sistema e recebe a volta num endereço
/// local (<c>http://127.0.0.1:porta/caminho</c>), com porta escolhida na hora (RFC 8252, seção 7.3).
/// Só escuta no 127.0.0.1: nada fica exposto na rede. Um login por vez.
/// </summary>
public sealed class NavegadorRetornoLocal : INavegadorBts, IDisposable
{
    private readonly Func<Uri, Task> _abrir;
    private TcpListener? _ouvinte;

    /// <param name="abrir">Como abrir o navegador. No MAUI: <c>u =&gt; Launcher.Default.OpenAsync(u)</c>. Padrão: navegador do sistema.</param>
    public NavegadorRetornoLocal(Func<Uri, Task>? abrir = null) => _abrir = abrir ?? AbrirNoSistema;

    /// <summary>Texto da página que aparece no navegador depois do login.</summary>
    public string MensagemFinal { get; set; } = "Pronto. Pode fechar esta aba e voltar ao aplicativo.";

    public Task<Uri> PrepararRetornoAsync(Uri cadastrado, CancellationToken ct)
    {
        if (cadastrado.Scheme != Uri.UriSchemeHttp || cadastrado.Host != "127.0.0.1")
            throw new BtsException("Para apps de computador, cadastre e use o retorno http://127.0.0.1/caminho.");
        Parar();
        _ouvinte = new TcpListener(IPAddress.Loopback, 0);
        _ouvinte.Start();
        var porta = ((IPEndPoint)_ouvinte.LocalEndpoint).Port;
        return Task.FromResult(new UriBuilder(cadastrado) { Port = porta }.Uri);
    }

    public async Task<Uri> AbrirAsync(Uri autorizar, Uri retorno, CancellationToken ct)
    {
        var ouvinte = _ouvinte ?? throw new InvalidOperationException("Chame PrepararRetornoAsync antes.");
        try
        {
            await _abrir(autorizar);
            while (true)
            {
                using var cliente = await ouvinte.AcceptTcpClientAsync(ct);
                var stream = cliente.GetStream();
                stream.ReadTimeout = 5000;
                var linha = await PrimeiraLinhaAsync(stream, ct); // "GET /caminho?code=...&state=... HTTP/1.1"
                var partes = linha.Split(' ');
                if (partes.Length < 3 || partes[0] != "GET" || !partes[1].StartsWith('/'))
                {
                    await ResponderAsync(stream, 400, "Pedido inválido.", ct);
                    continue;
                }
                var volta = new Uri(retorno, partes[1]);
                if (volta.AbsolutePath != retorno.AbsolutePath)
                {
                    await ResponderAsync(stream, 404, "", ct); // favicon e afins
                    continue;
                }
                await ResponderAsync(stream, 200, MensagemFinal, ct);
                return volta;
            }
        }
        finally
        {
            Parar();
        }
    }

    private static async Task<string> PrimeiraLinhaAsync(NetworkStream stream, CancellationToken ct)
    {
        var buffer = new byte[8192];
        var total = 0;
        while (total < buffer.Length)
        {
            var lidos = await stream.ReadAsync(buffer.AsMemory(total), ct);
            if (lidos == 0) break;
            total += lidos;
            var fim = Array.IndexOf(buffer, (byte)'\n', 0, total);
            if (fim >= 0) return Encoding.ASCII.GetString(buffer, 0, fim).TrimEnd('\r');
        }
        return Encoding.ASCII.GetString(buffer, 0, total);
    }

    private static async Task ResponderAsync(NetworkStream stream, int status, string mensagem, CancellationToken ct)
    {
        var corpo = Encoding.UTF8.GetBytes(
            "<!doctype html><html lang=\"pt-BR\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">" +
            $"<title>BTS</title><p style=\"font:18px system-ui,sans-serif;margin:40px\">{WebUtility.HtmlEncode(mensagem)}</p></html>");
        var texto = status switch { 200 => "OK", 404 => "Not Found", _ => "Bad Request" };
        var cabecalho = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status} {texto}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n" +
            "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nReferrer-Policy: no-referrer\r\n" +
            $"Content-Length: {corpo.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(cabecalho, ct);
        await stream.WriteAsync(corpo, ct);
    }

    private static Task AbrirNoSistema(Uri u)
    {
        Process.Start(new ProcessStartInfo(u.ToString()) { UseShellExecute = true });
        return Task.CompletedTask;
    }

    private void Parar()
    {
        _ouvinte?.Stop();
        _ouvinte = null;
    }

    public void Dispose() => Parar();
}
