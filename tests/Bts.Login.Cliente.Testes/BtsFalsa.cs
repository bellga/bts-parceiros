using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Bts.Login.Cliente.Testes;

/// <summary>
/// BTS falsa, inteira em memória: descoberta, chaves, autorização (pelo navegador falso), token e revogação.
/// Confere o PKCE de verdade (S256).
/// </summary>
public sealed class BtsFalsa : HttpMessageHandler, INavegadorBts
{
    public const string Emissor = "https://bts.teste/";
    public const string ClientId = "app-teste";

    // Chaves próprias de cada BTS falsa (nada compartilhado entre testes). A "estranha" usa o mesmo kid:
    // o que tem de barrar o token é a assinatura, não a falta da chave.
    public RsaSecurityKey Chave { get; }
    public RsaSecurityKey ChaveEstranha { get; }

    public BtsFalsa()
    {
        var kid = Guid.NewGuid().ToString("N");
        Chave = new RsaSecurityKey(RSA.Create(2048)) { KeyId = kid };
        ChaveEstranha = new RsaSecurityKey(RSA.Create(2048)) { KeyId = kid };
        ChaveAssinatura = Chave;
    }

    // O que o "navegador" faz
    public Func<Uri, Uri, Uri>? Volta { get; set; } // (autorizar, retorno) => endereço de volta
    public bool Cancelar { get; set; }

    // O que a "BTS" emite
    public SecurityKey ChaveAssinatura { get; set; }
    public string Audiencia { get; set; } = ClientId;
    public string? NonceForcado { get; set; }
    public DateTime? Expira { get; set; }
    public int[] Niveis { get; set; } = [1, 3];
    public bool RefreshValido { get; set; } = true;

    public Uri? UltimoAutorizar { get; private set; }
    public List<string> Revogados { get; } = [];
    public Dictionary<string, string> UltimoToken { get; private set; } = [];

    private readonly Dictionary<string, (string Desafio, string Nonce, string Retorno)> _codigos = [];

    public Task<Uri> AbrirAsync(Uri autorizar, Uri retorno, CancellationToken ct)
    {
        UltimoAutorizar = autorizar;
        if (Cancelar) throw new TaskCanceledException();
        return Task.FromResult(Volta is not null ? Volta(autorizar, retorno) : AbrirSemVolta(autorizar, retorno));
    }

    /// <summary>O que a BTS faz depois do "Permitir": cria o código e manda de volta.</summary>
    public Uri AbrirSemVolta(Uri autorizar, Uri retorno)
    {
        UltimoAutorizar = autorizar;
        var q = Consulta(autorizar.Query);
        var code = "c" + Guid.NewGuid().ToString("N");
        lock (_codigos) _codigos[code] = (q["code_challenge"], q["nonce"], q["redirect_uri"]);
        return new Uri($"{retorno}?code={code}&state={Uri.EscapeDataString(q["state"])}&iss={Uri.EscapeDataString(Emissor)}");
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        var caminho = req.RequestUri!.AbsolutePath;
        switch (caminho)
        {
            case "/.well-known/openid-configuration":
                return Json(new Dictionary<string, object>
                {
                    ["issuer"] = Emissor,
                    ["authorization_endpoint"] = Emissor + "connect/authorize",
                    ["token_endpoint"] = Emissor + "connect/token",
                    ["revocation_endpoint"] = Emissor + "connect/revoke",
                    ["jwks_uri"] = Emissor + ".well-known/jwks",
                    ["response_types_supported"] = new[] { "code" },
                    ["subject_types_supported"] = new[] { "public" },
                    ["id_token_signing_alg_values_supported"] = new[] { "RS256" }
                });
            case "/.well-known/jwks":
                var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(Chave);
                return Json(new { keys = new[] { new { kty = jwk.Kty, kid = jwk.Kid, use = "sig", alg = "RS256", n = jwk.N, e = jwk.E } } });
            case "/connect/revoke":
                Revogados.Add(Consulta(await req.Content!.ReadAsStringAsync(ct))["token"]);
                return new HttpResponseMessage(HttpStatusCode.OK);
            case "/connect/token":
                var f = Consulta(await req.Content!.ReadAsStringAsync(ct));
                UltimoToken = f;
                if (f["client_id"] != ClientId) return Erro("invalid_client");
                if (f["grant_type"] == "refresh_token")
                    return RefreshValido ? Tokens(null) : Erro("invalid_grant");
                (string Desafio, string Nonce, string Retorno) c;
                lock (_codigos) if (!_codigos.Remove(f["code"], out c)) return Erro("invalid_grant");
                var desafio = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(f["code_verifier"])));
                if (desafio != c.Desafio || f["redirect_uri"] != c.Retorno) return Erro("invalid_grant");
                return Tokens(NonceForcado ?? c.Nonce);
            default:
                return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    private HttpResponseMessage Tokens(string? nonce)
    {
        var agora = DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "sub-do-app",
            ["name"] = "Maria Teste",
            ["email"] = "maria@teste.com",
            ["email_verified"] = true,
            ["phone_number"] = "+5511999990000",
            ["bts_niveis"] = Niveis
        };
        if (nonce is not null) claims["nonce"] = nonce;
        var expira = Expira ?? agora.AddMinutes(15);
        var idToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Emissor,
            Audience = Audiencia,
            IssuedAt = expira.AddMinutes(-15),
            NotBefore = expira.AddMinutes(-15),
            Expires = expira,
            SigningCredentials = new SigningCredentials(ChaveAssinatura, SecurityAlgorithms.RsaSha256),
            Claims = claims
        });
        return Json(new
        {
            access_token = "at-" + Guid.NewGuid().ToString("N"),
            token_type = "Bearer",
            expires_in = 900,
            refresh_token = "rt-" + Guid.NewGuid().ToString("N"),
            id_token = idToken
        });
    }

    private static HttpResponseMessage Erro(string erro) =>
        new(HttpStatusCode.BadRequest) { Content = new StringContent(JsonSerializer.Serialize(new { error = erro }), Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Json(object o) =>
        new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(o), Encoding.UTF8, "application/json") };

    public static Dictionary<string, string> Consulta(string s) =>
        s.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p.Length > 1 ? p[1].Replace('+', ' ') : ""));

    private static string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
