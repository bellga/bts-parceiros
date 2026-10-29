using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Bts.Login.AspNetCore.Testes;

/// <summary>
/// Site de parceiro de teste + uma BTS falsa (só o endpoint de token, pelo backchannel).
/// Nada vai para a rede.
/// </summary>
public sealed class SiteTeste : IAsyncDisposable
{
    public const string Emissor = "https://bts.teste/";
    public const string ClientId = "parceiro-teste";

    public static readonly RsaSecurityKey Chave = new(RSA.Create(2048)) { KeyId = "chave-teste" };
    public static readonly RsaSecurityKey ChaveEstranha = new(RSA.Create(2048)) { KeyId = "chave-teste" };

    private readonly IHost _host;
    public BtsFalsa Bts { get; } = new();
    public HttpClient Cliente { get; }

    private SiteTeste(IHost host)
    {
        _host = host;
        Cliente = host.GetTestServer().CreateClient();
        Cliente.BaseAddress = new Uri("https://parceiro.teste/");
    }

    public static async Task<SiteTeste> CriarAsync(Action<BtsLoginOptions>? configurar = null,
        Action<Microsoft.AspNetCore.Authentication.AuthenticationBuilder, IServiceCollection>? extra = null,
        Action<Microsoft.AspNetCore.Routing.IEndpointRouteBuilder>? rotas = null)
    {
        BtsFalsa? bts = null;
        var host = new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting();
            var auth = s.AddEntrarComBts(o =>
            {
                o.Emissor = Emissor;
                o.ClientId = ClientId;
                o.Segredo = "segredo-teste";
                o.Escopos.Add(BtsEscopos.Niveis);
                configurar?.Invoke(o);
            });
            extra?.Invoke(auth, s);
            s.Configure<OpenIdConnectOptions>(BtsPadroes.Esquema, o =>
            {
                var cfg = new OpenIdConnectConfiguration
                {
                    Issuer = Emissor,
                    AuthorizationEndpoint = Emissor + "connect/authorize",
                    TokenEndpoint = Emissor + "connect/token",
                    EndSessionEndpoint = Emissor + "connect/logout"
                };
                cfg.SigningKeys.Add(Chave);
                o.Configuration = cfg;
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(cfg);
                o.BackchannelHttpHandler = bts!;
            });
            s.AddAuthorization(o => o.AddPolicy("celular", p => p.ExigirNivelBts(3)));
        }).Configure(app =>
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(e =>
            {
                e.MapEntrarComBts();
                e.MapGet("/eu", (ClaimsPrincipal u) => Results.Ok(new
                {
                    id = u.IdBts(),
                    conta = u.ContaParceiro(),
                    nome = u.NomeBts(),
                    email = u.EmailBts(),
                    niveis = u.NiveisBts().ToArray()
                })).RequireAuthorization();
                e.MapGet("/so-com-celular", () => "ok").RequireAuthorization("celular");
                rotas?.Invoke(e);
            });
        }));
        var site = new SiteTeste(await host.StartAsync());
        bts = site.Bts;
        return site;
    }

    public async ValueTask DisposeAsync()
    {
        Cliente.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}

/// <summary>Endpoint de token da BTS: confere o pedido e devolve um id_token assinado.</summary>
public sealed class BtsFalsa : HttpMessageHandler
{
    public string? Nonce { get; set; }
    public int[] Niveis { get; set; } = [1, 3];
    public string Sub { get; set; } = "sub-do-parceiro";
    public string Email { get; set; } = "maria@teste.com";
    public bool EmailConfirmado { get; set; } = true;
    public SecurityKey ChaveAssinatura { get; set; } = SiteTeste.Chave;
    public string Audiencia { get; set; } = SiteTeste.ClientId;
    public Dictionary<string, string> UltimoPedido { get; private set; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        if (req.RequestUri!.AbsolutePath != "/connect/token") return new HttpResponseMessage(HttpStatusCode.NotFound);
        var corpo = await req.Content!.ReadAsStringAsync(ct);
        UltimoPedido = corpo.Split('&').Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p.Length > 1 ? p[1].Replace('+', ' ') : ""));

        var agora = DateTime.UtcNow;
        var idToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = SiteTeste.Emissor,
            Audience = Audiencia,
            IssuedAt = agora,
            NotBefore = agora,
            Expires = agora.AddMinutes(15),
            SigningCredentials = new SigningCredentials(ChaveAssinatura, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = Sub,
                ["name"] = "Maria Teste",
                ["email"] = Email,
                ["email_verified"] = EmailConfirmado,
                ["nonce"] = Nonce ?? "",
                ["bts_niveis"] = Niveis
            }
        });
        var json = JsonSerializer.Serialize(new
        {
            access_token = "access-teste",
            token_type = "Bearer",
            expires_in = 900,
            id_token = idToken
        });
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
    }
}
