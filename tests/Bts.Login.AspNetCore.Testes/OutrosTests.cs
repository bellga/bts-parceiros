using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
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

public class ClaimsTests
{
    private static ClaimsPrincipal Pessoa(params Claim[] c) => new(new ClaimsIdentity(c, "teste"));

    [Fact]
    public void Niveis_vindos_como_varios_claims()
    {
        var u = Pessoa(new Claim(BtsClaims.Niveis, "3"), new Claim(BtsClaims.Niveis, "1"));
        Assert.Equal([1, 3], u.NiveisBts());
        Assert.True(u.TemNivelBts(3));
        Assert.False(u.TemNivelBts(2));
    }

    [Fact]
    public void Niveis_vindos_como_lista_json()
    {
        var u = Pessoa(new Claim(BtsClaims.Niveis, "[1,3]", JsonClaimValueTypes.JsonArray));
        Assert.Equal([1, 3], u.NiveisBts());
    }

    [Fact]
    public void Niveis_invalidos_ou_ausentes_nao_contam()
    {
        Assert.Empty(Pessoa().NiveisBts());
        Assert.Empty(Pessoa(new Claim(BtsClaims.Niveis, "abc"), new Claim(BtsClaims.Niveis, "[x")).NiveisBts());
        Assert.Empty(Pessoa(new Claim(BtsClaims.Niveis, "-3")).NiveisBts());
    }

    [Theory]
    [InlineData("/painel", "/painel")]
    [InlineData("/a?b=1", "/a?b=1")]
    [InlineData(null, "/")]
    [InlineData("", "/")]
    [InlineData("painel", "/")]
    [InlineData("https://mal.exemplo", "/")]
    [InlineData("//mal.exemplo", "/")]
    [InlineData("/\\mal.exemplo", "/")]
    [InlineData("/a\r\nLocation: x", "/")]
    public void Retorno_so_aceita_caminho_local(string? retorno, string esperado) =>
        Assert.Equal(esperado, BtsExtensions.SoLocal(retorno));
}

public class BotaoTests
{
    [Fact]
    public void Botao_escuro_com_texto()
    {
        var html = BtsBotao.Html("/entrar/bts").Value!;
        Assert.Contains("class=\"bts-botao bts-escuro\"", html);
        Assert.Contains("href=\"/entrar/bts\"", html);
        Assert.Contains("<span>Entrar com BTS</span>", html);
        Assert.DoesNotContain("<script", html);
        Assert.DoesNotContain("style=", html); // nada inline: funciona com CSP rígida
    }

    [Fact]
    public void Botao_claro_continuar_e_so_icone()
    {
        Assert.Contains("Continuar com BTS", BtsBotao.Html("/e", BtsTema.Claro, BtsTexto.Continuar).Value);
        var icone = BtsBotao.Html("/e", BtsTema.Claro, soIcone: true).Value!;
        Assert.Contains("bts-so-icone bts-claro", icone);
        Assert.Contains("aria-label=\"Entrar com BTS\"", icone);
    }

    [Fact]
    public void Endereco_do_botao_leva_o_retorno_local_e_escapa_o_href()
    {
        Assert.Equal("/entrar/bts?retorno=%2Fcarrinho%3Fa%3D1", BtsBotao.Endereco("/entrar/bts", "/carrinho?a=1"));
        Assert.Equal("/entrar/bts", BtsBotao.Endereco("/entrar/bts", "https://mal.exemplo"));
        Assert.Contains("href=\"/x?a=1&amp;b=&quot;2\"", BtsBotao.Html("/x?a=1&b=\"2").Value);
    }
}

public class BearerTests
{
    private static async Task<IHost> ApiAsync()
    {
        var host = new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting();
            s.AddAuthentication(BtsPadroes.EsquemaBearer)
                .AddBtsBearer(o => { o.Emissor = SiteTeste.Emissor; o.ClientIds.Add("app-parceiro"); });
            s.Configure<JwtBearerOptions>(BtsPadroes.EsquemaBearer, o =>
            {
                var cfg = new OpenIdConnectConfiguration { Issuer = SiteTeste.Emissor };
                cfg.SigningKeys.Add(SiteTeste.Chave);
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(cfg);
            });
            s.AddAuthorization();
        }).Configure(app =>
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(e => e.MapGet("/dados", (ClaimsPrincipal u) => u.IdBts()).RequireAuthorization());
        }));
        return await host.StartAsync();
    }

    private static string Token(string aud = "app-parceiro", string tipo = "at+jwt", SecurityKey? chave = null,
        string emissor = SiteTeste.Emissor) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = emissor,
            Audience = aud,
            TokenType = tipo,
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(chave ?? SiteTeste.Chave, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["sub"] = "sub-app" }
        });

    private static async Task<HttpResponseMessage> ChamarAsync(IHost host, string? token)
    {
        var cliente = host.GetTestServer().CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/dados");
        if (token is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await cliente.SendAsync(req);
    }

    [Fact]
    public async Task Access_token_do_app_do_parceiro_e_aceito()
    {
        using var host = await ApiAsync();
        var r = await ChamarAsync(host, Token());
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("sub-app", await r.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("outro-app", "at+jwt", false, SiteTeste.Emissor)] // token de outro parceiro
    [InlineData("app-parceiro", "JWT", false, SiteTeste.Emissor)]  // id_token no lugar do access token
    [InlineData("app-parceiro", "at+jwt", true, SiteTeste.Emissor)] // assinatura de outra chave
    [InlineData("app-parceiro", "at+jwt", false, "https://falsa.exemplo/")]
    public async Task Tokens_errados_sao_recusados(string aud, string tipo, bool outraChave, string emissor)
    {
        using var host = await ApiAsync();
        var r = await ChamarAsync(host, Token(aud, tipo, outraChave ? SiteTeste.ChaveEstranha : null, emissor));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task Sem_token_e_recusado()
    {
        using var host = await ApiAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, (await ChamarAsync(host, null)).StatusCode);
    }
}

public class TagHelperTests
{
    [Fact]
    public void Tag_helper_usa_a_rota_configurada_e_o_retorno()
    {
        var opcoes = Microsoft.Extensions.Options.Options.Create(new BtsLoginOptions { ClientId = "x", CaminhoEntrar = "/login/bts" });
        var th = new BtsBotaoTagHelper(opcoes) { Tema = BtsTema.Claro, Texto = BtsTexto.Continuar, Retorno = "/conta" };
        var ctx = new Microsoft.AspNetCore.Razor.TagHelpers.TagHelperContext([], new Dictionary<object, object>(), "id");
        var saida = new Microsoft.AspNetCore.Razor.TagHelpers.TagHelperOutput("bts-botao", [],
            (_, _) => Task.FromResult<Microsoft.AspNetCore.Razor.TagHelpers.TagHelperContent>(
                new Microsoft.AspNetCore.Razor.TagHelpers.DefaultTagHelperContent()));
        th.Process(ctx, saida);
        Assert.Null(saida.TagName);
        var html = saida.Content.GetContent();
        Assert.Contains("href=\"/login/bts?retorno=%2Fconta\"", html);
        Assert.Contains("bts-claro", html);
        Assert.Contains("Continuar com BTS", html);
    }
}
