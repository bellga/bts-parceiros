using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Bts.Login.Cliente;

/// <summary>Configuração do app do parceiro (cliente público, sem segredo).</summary>
public sealed class BtsClienteOptions
{
    public const string EmissorPadrao = "https://login.bellga.tech/";

    public string Emissor { get; set; } = EmissorPadrao;

    /// <summary>Identificador do app, recebido no cadastro do parceiro.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>
    /// Endereço de volta cadastrado na BTS. Celular: esquema próprio do app (ex.: <c>com.exemplo.app:/bts</c>).
    /// Computador: <c>http://127.0.0.1/bts</c> (a porta é escolhida na hora; cadastre sem porta).
    /// </summary>
    public string RetornoUri { get; set; } = "";

    /// <summary>Escopos pedidos (<c>openid</c> sempre vai). Inclua <c>offline_access</c> para continuar conectado.</summary>
    public ISet<string> Escopos { get; } = new HashSet<string> { "openid", "profile", "email" };

    /// <summary>Tempo máximo esperando a pessoa no navegador.</summary>
    public TimeSpan EsperaMaxima { get; set; } = TimeSpan.FromMinutes(5);

    internal void Validar()
    {
        if (string.IsNullOrWhiteSpace(ClientId)) throw new InvalidOperationException("Bts: informe o ClientId do app.");
        if (!Uri.TryCreate(Emissor, UriKind.Absolute, out var e) || (e.Scheme != Uri.UriSchemeHttps && !e.IsLoopback))
            throw new InvalidOperationException("Bts: o Emissor precisa ser https.");
        if (!Uri.TryCreate(RetornoUri, UriKind.Absolute, out _))
            throw new InvalidOperationException("Bts: informe o RetornoUri cadastrado na BTS.");
    }
}

/// <summary>Quem abre o login da BTS e devolve o endereço de volta (com o code). Cada plataforma tem o seu.</summary>
public interface INavegadorBts
{
    /// <param name="autorizar">Página de login/autorização da BTS.</param>
    /// <param name="retorno">Endereço de volta exato (com a porta, no caso do retorno local).</param>
    /// <returns>O endereço de volta completo, com <c>code</c> e <c>state</c> (ou <c>error</c>).</returns>
    Task<Uri> AbrirAsync(Uri autorizar, Uri retorno, CancellationToken ct);

    /// <summary>Retorno local: escolhe a porta e devolve o endereço exato. Outros navegadores devolvem o próprio endereço.</summary>
    Task<Uri> PrepararRetornoAsync(Uri cadastrado, CancellationToken ct) => Task.FromResult(cadastrado);
}

/// <summary>A pessoa conectada (só os dados dos escopos que ela permitiu).</summary>
public sealed record BtsPessoa(
    string Id, string? Nome, string? Email, bool EmailConfirmado, string? Celular, IReadOnlySet<int> Niveis)
{
    public bool TemNivel(int nivel) => Niveis.Contains(nivel);
}

/// <summary>Resultado do login. Guarde o <see cref="RefreshToken"/> em armazenamento seguro (SecureStorage).</summary>
public sealed record BtsSessao(BtsPessoa Pessoa, string AccessToken, DateTimeOffset AccessTokenExpiraEm,
    string? RefreshToken, string IdToken);

public class BtsException(string mensagem, string? erro = null) : Exception(mensagem)
{
    /// <summary>Código de erro do OpenID Connect (ex.: invalid_grant), quando houver.</summary>
    public string? Erro { get; } = erro;
}

/// <summary>A pessoa fechou o navegador ou tocou em Cancelar.</summary>
public sealed class BtsCanceladoException() : BtsException("Login cancelado.", "access_denied");

/// <summary>Login com a BTS em apps: navegador do sistema + Authorization Code + PKCE (RFC 8252).</summary>
public sealed class BtsCliente
{
    private readonly BtsClienteOptions _o;
    private readonly INavegadorBts _navegador;
    private readonly HttpClient _http;
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _config;
    private readonly TimeProvider _relogio;
    private readonly Uri _endDescoberta;

    /// <param name="http">Opcional: um HttpClient seu (ex.: com certificate pinning).</param>
    public BtsCliente(BtsClienteOptions opcoes, INavegadorBts navegador, HttpClient? http = null, TimeProvider? relogio = null)
    {
        opcoes.Validar();
        _o = opcoes;
        _navegador = navegador;
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _relogio = relogio ?? TimeProvider.System;
        var emissor = _o.Emissor.EndsWith('/') ? _o.Emissor : _o.Emissor + "/";
        _endDescoberta = new Uri(emissor + ".well-known/openid-configuration");
        _config = new ConfigurationManager<OpenIdConnectConfiguration>(
            _endDescoberta.ToString(), new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(_http) { RequireHttps = _endDescoberta.Scheme == Uri.UriSchemeHttps });
    }

    /// <summary>Abre o login da BTS e devolve a pessoa e os tokens.</summary>
    /// <param name="forcarSenha">Pede a senha de novo mesmo com a sessão da BTS aberta no navegador.</param>
    /// <exception cref="BtsCanceladoException">A pessoa cancelou.</exception>
    public async Task<BtsSessao> EntrarAsync(bool forcarSenha = false, CancellationToken ct = default)
    {
        var cfg = await ConfiguracaoAsync(ct);
        var verificador = Base64Url(RandomNumberGenerator.GetBytes(32));
        var desafio = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verificador)));
        var state = Base64Url(RandomNumberGenerator.GetBytes(16));
        var nonce = Base64Url(RandomNumberGenerator.GetBytes(16));

        using var tempo = CancellationTokenSource.CreateLinkedTokenSource(ct);
        tempo.CancelAfter(_o.EsperaMaxima);
        var retorno = await _navegador.PrepararRetornoAsync(new Uri(_o.RetornoUri), tempo.Token);

        var parametros = new Dictionary<string, string>
        {
            ["client_id"] = _o.ClientId,
            ["redirect_uri"] = retorno.ToString(),
            ["response_type"] = "code",
            ["scope"] = string.Join(' ', new[] { "openid" }.Concat(_o.Escopos.Where(e => e != "openid"))),
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = desafio,
            ["code_challenge_method"] = "S256"
        };
        if (forcarSenha) parametros["prompt"] = "login";
        var autorizar = new Uri(cfg.AuthorizationEndpoint + "?" +
            string.Join('&', parametros.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}")));

        Uri volta;
        try { volta = await _navegador.AbrirAsync(autorizar, retorno, tempo.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new BtsCanceladoException(); }
        catch (TaskCanceledException) { throw new BtsCanceladoException(); }

        var resposta = LerConsulta(volta);
        resposta.TryGetValue("error", out var erro);
        if (erro == "access_denied") throw new BtsCanceladoException();
        if (!resposta.TryGetValue("state", out var stateVolta) || !IguaisTempoConstante(state, stateVolta))
            throw new BtsException("Resposta do login não confere (state).");
        if (erro is not null) throw new BtsException($"A BTS recusou o login: {erro}.", erro);
        // RFC 9207: quando a BTS informa o emissor na volta, ele precisa ser o esperado (evita mistura de provedores)
        if (resposta.TryGetValue("iss", out var iss) && iss != cfg.Issuer)
            throw new BtsException("Resposta do login veio de outro emissor.");
        if (!resposta.TryGetValue("code", out var code) || code.Length == 0)
            throw new BtsException("Resposta do login sem código.");

        var tokens = await PedirTokensAsync(cfg, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = retorno.ToString(),
            ["code_verifier"] = verificador,
            ["client_id"] = _o.ClientId
        }, ct);
        return await SessaoAsync(cfg, tokens, nonce, null, ct);
    }

    /// <summary>Renova o access token com o refresh token (escopo <c>offline_access</c>). O refresh token muda: guarde o novo.</summary>
    /// <exception cref="BtsException">Com <see cref="BtsException.Erro"/> = invalid_grant: sessão encerrada; peça login de novo.</exception>
    public async Task<BtsSessao> RenovarAsync(string refreshToken, CancellationToken ct = default)
    {
        var cfg = await ConfiguracaoAsync(ct);
        var tokens = await PedirTokensAsync(cfg, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = _o.ClientId
        }, ct);
        return await SessaoAsync(cfg, tokens, null, refreshToken, ct);
    }

    /// <summary>Sai: revoga o refresh token na BTS. Apague também os tokens guardados no app.</summary>
    public async Task SairAsync(BtsSessao sessao, CancellationToken ct = default)
    {
        if (sessao.RefreshToken is null) return;
        string? revogar;
        try
        {
            var doc = await new HttpDocumentRetriever(_http) { RequireHttps = _endDescoberta.Scheme == Uri.UriSchemeHttps }
                .GetDocumentAsync(_endDescoberta.ToString(), ct);
            revogar = JsonDocument.Parse(doc).RootElement.TryGetProperty("revocation_endpoint", out var r) ? r.GetString() : null;
        }
        catch (Exception e) when (e is not OperationCanceledException) { return; } // sem rede: o token vence sozinho
        if (string.IsNullOrEmpty(revogar)) return;
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = sessao.RefreshToken,
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = _o.ClientId
        });
        try { using var _ = await _http.PostAsync(revogar, form, ct); }
        catch (HttpRequestException) { } // sem rede: o token vence sozinho (14 dias)
    }

    private async Task<OpenIdConnectConfiguration> ConfiguracaoAsync(CancellationToken ct)
    {
        try { return await _config.GetConfigurationAsync(ct); }
        catch (Exception e) when (e is not OperationCanceledException)
        { throw new BtsException("Não foi possível falar com a BTS. Confira a internet e tente de novo."); }
    }

    private async Task<RespostaToken> PedirTokensAsync(OpenIdConnectConfiguration cfg, Dictionary<string, string> campos,
        CancellationToken ct)
    {
        using var form = new FormUrlEncodedContent(campos);
        using var resp = await _http.PostAsync(cfg.TokenEndpoint, form, ct);
        RespostaToken? corpo = null;
        try { corpo = await resp.Content.ReadFromJsonAsync<RespostaToken>(ct); } catch (JsonException) { }
        if (!resp.IsSuccessStatusCode || corpo is null || string.IsNullOrEmpty(corpo.AccessToken))
            throw new BtsException(
                corpo?.Erro == "invalid_grant" ? "A sessão da BTS terminou. Entre de novo." : "A BTS recusou o login.",
                corpo?.Erro);
        return corpo;
    }

    private async Task<BtsSessao> SessaoAsync(OpenIdConnectConfiguration cfg, RespostaToken t, string? nonce,
        string? refreshAnterior, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(t.IdToken)) throw new BtsException("A BTS não devolveu o id_token.");
        var validacao = await new JsonWebTokenHandler().ValidateTokenAsync(t.IdToken, new TokenValidationParameters
        {
            ValidIssuer = cfg.Issuer,
            ValidAudience = _o.ClientId,
            IssuerSigningKeys = cfg.SigningKeys,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            LifetimeValidator = (antes, expira, _, p) =>
            {
                var agora = _relogio.GetUtcNow().UtcDateTime;
                return (antes is null || antes <= agora + p.ClockSkew) && expira is not null && expira >= agora - p.ClockSkew;
            }
        });
        // O tipo da falha ajuda no suporte (assinatura, validade, audiência...) e não expõe o token
        if (!validacao.IsValid)
            throw new BtsException($"O id_token da BTS não é válido ({validacao.Exception?.GetType().Name ?? "motivo desconhecido"}).");
        var jwt = (JsonWebToken)validacao.SecurityToken;
        if (nonce is not null && (!jwt.TryGetPayloadValue<string>("nonce", out var n) || !IguaisTempoConstante(nonce, n)))
            throw new BtsException("O id_token não confere com este login (nonce).");

        var pessoa = new BtsPessoa(
            jwt.Subject,
            Texto(jwt, "name"),
            Texto(jwt, "email"),
            jwt.TryGetPayloadValue<bool>("email_verified", out var ev) && ev,
            Texto(jwt, "phone_number"),
            Niveis(jwt));
        return new BtsSessao(pessoa, t.AccessToken!,
            _relogio.GetUtcNow().AddSeconds(t.ExpiraEm > 0 ? t.ExpiraEm : 900), t.RefreshToken ?? refreshAnterior, t.IdToken);
    }

    private static string? Texto(JsonWebToken jwt, string claim) =>
        jwt.TryGetPayloadValue<string>(claim, out var v) ? v : null;

    internal static IReadOnlySet<int> Niveis(JsonWebToken jwt)
    {
        var niveis = new SortedSet<int>();
        if (jwt.TryGetPayloadValue<JsonElement>("bts_niveis", out var e) && e.ValueKind == JsonValueKind.Array)
            foreach (var x in e.EnumerateArray())
                if (x.TryGetInt32(out var n) && n > 0) niveis.Add(n);
        return niveis;
    }

    internal static Dictionary<string, string> LerConsulta(Uri volta)
    {
        // A volta pode trazer os parâmetros na consulta (?code=) — o padrão da BTS
        var consulta = volta.Query.TrimStart('?');
        var dados = new Dictionary<string, string>();
        foreach (var par in consulta.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var p = par.Split('=', 2);
            var chave = Uri.UnescapeDataString(p[0].Replace('+', ' '));
            if (!dados.TryAdd(chave, Uri.UnescapeDataString((p.Length > 1 ? p[1] : "").Replace('+', ' '))))
                throw new BtsException("Resposta do login com parâmetro repetido.");
        }
        return dados;
    }

    private static bool IguaisTempoConstante(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static string Base64Url(byte[] dados) =>
        Convert.ToBase64String(dados).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record RespostaToken(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken,
        [property: JsonPropertyName("id_token")] string? IdToken,
        [property: JsonPropertyName("expires_in")] int ExpiraEm,
        [property: JsonPropertyName("error")] string? Erro);
}
