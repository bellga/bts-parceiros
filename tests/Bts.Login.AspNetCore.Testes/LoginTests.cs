using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Bts.Login.AspNetCore.Testes;

public class LoginTests
{
    private static Dictionary<string, string> Cookies(HttpResponseMessage r) =>
        (r.Headers.TryGetValues("Set-Cookie", out var v) ? v : [])
        .Select(c => c.Split(';')[0].Split('=', 2))
        .Where(p => p.Length == 2 && p[1].Length > 0)
        .ToDictionary(p => p[0], p => p[1]);

    private static HttpRequestMessage Get(string url, IDictionary<string, string>? cookies = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (cookies is { Count: > 0 }) req.Headers.Add("Cookie", string.Join("; ", cookies.Select(c => $"{c.Key}={c.Value}")));
        return req;
    }

    /// <summary>Clica no botão, "volta" da BTS com um código e devolve a resposta da volta + os cookies.</summary>
    private static async Task<(HttpResponseMessage Volta, Dictionary<string, string> Cookies, Uri Autorizar)> EntrarAsync(
        SiteTeste site, string entrar = "/entrar/bts")
    {
        var desafio = await site.Cliente.SendAsync(Get(entrar));
        Assert.Equal(HttpStatusCode.Redirect, desafio.StatusCode);
        var autorizar = desafio.Headers.Location!;
        var q = QueryHelpers.ParseQuery(autorizar.Query);
        site.Bts.Nonce = q["nonce"];
        var cookies = Cookies(desafio);
        var volta = await site.Cliente.SendAsync(Get(
            $"/signin-bts?code=codigo-teste&state={Uri.EscapeDataString(q["state"]!)}&iss={Uri.EscapeDataString(SiteTeste.Emissor)}",
            cookies));
        foreach (var c in Cookies(volta)) cookies[c.Key] = c.Value;
        return (volta, cookies, autorizar);
    }

    [Fact]
    public async Task Botao_leva_para_a_bts_com_pkce_e_os_escopos()
    {
        await using var site = await SiteTeste.CriarAsync(o => o.Escopos.Add(BtsEscopos.Celular));
        var r = await site.Cliente.SendAsync(Get("/entrar/bts"));

        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var url = r.Headers.Location!;
        Assert.Equal("https://bts.teste/connect/authorize", url.GetLeftPart(UriPartial.Path));
        var q = QueryHelpers.ParseQuery(url.Query);
        Assert.Equal(SiteTeste.ClientId, q["client_id"]);
        Assert.Equal("code", q["response_type"]);
        Assert.False(q.ContainsKey("response_mode")); // padrão do code = query (a BTS não usa form_post)
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.False(string.IsNullOrEmpty(q["code_challenge"]));
        Assert.Equal("https://parceiro.teste/signin-bts", q["redirect_uri"]);
        Assert.Equal(["openid", "profile", "email", "bts.niveis", "phone"], q["scope"].ToString().Split(' '));
    }

    [Fact]
    public async Task Volta_da_bts_conecta_a_pessoa_no_site_com_os_dados_e_niveis()
    {
        await using var site = await SiteTeste.CriarAsync();
        var (volta, cookies, _) = await EntrarAsync(site, "/entrar/bts?retorno=%2Fpainel%3Fx%3D1");

        Assert.Equal(HttpStatusCode.Redirect, volta.StatusCode);
        Assert.Equal("/painel?x=1", volta.Headers.Location!.OriginalString);
        Assert.Contains("__Host-bts-parceiro", cookies.Keys);

        // A troca do código foi feita com PKCE e com o segredo do parceiro
        Assert.Equal("authorization_code", site.Bts.UltimoPedido["grant_type"]);
        Assert.Equal("codigo-teste", site.Bts.UltimoPedido["code"]);
        Assert.False(string.IsNullOrEmpty(site.Bts.UltimoPedido["code_verifier"]));
        Assert.Equal("segredo-teste", site.Bts.UltimoPedido["client_secret"]);

        var eu = await site.Cliente.SendAsync(Get("/eu", cookies));
        Assert.Equal(HttpStatusCode.OK, eu.StatusCode);
        var dados = JsonDocument.Parse(await eu.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("sub-do-parceiro", dados.GetProperty("id").GetString());
        Assert.Equal("Maria Teste", dados.GetProperty("nome").GetString());
        Assert.Equal("maria@teste.com", dados.GetProperty("email").GetString());
        Assert.Equal([1, 3], dados.GetProperty("niveis").EnumerateArray().Select(e => e.GetInt32()));

        Assert.Equal(HttpStatusCode.OK, (await site.Cliente.SendAsync(Get("/so-com-celular", cookies))).StatusCode);
    }

    [Theory]
    [InlineData("https%3A%2F%2Fmal.exemplo%2F")]
    [InlineData("%2F%2Fmal.exemplo")]
    [InlineData("%2F%5Cmal.exemplo")]
    public async Task Retorno_para_outro_site_vira_o_inicio(string retorno)
    {
        await using var site = await SiteTeste.CriarAsync();
        var (volta, _, _) = await EntrarAsync(site, "/entrar/bts?retorno=" + retorno);
        Assert.Equal("/", volta.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Sem_o_nivel_exigido_a_rota_e_negada()
    {
        await using var site = await SiteTeste.CriarAsync();
        site.Bts.Niveis = [1];
        var (_, cookies, _) = await EntrarAsync(site);

        Assert.Equal(HttpStatusCode.OK, (await site.Cliente.SendAsync(Get("/eu", cookies))).StatusCode);
        var r = await site.Cliente.SendAsync(Get("/so-com-celular", cookies));
        Assert.NotEqual(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task Sem_login_a_rota_protegida_manda_para_a_bts()
    {
        await using var site = await SiteTeste.CriarAsync();
        var r = await site.Cliente.SendAsync(Get("/eu"));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.StartsWith("https://bts.teste/connect/authorize", r.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Id_token_assinado_por_outra_chave_nao_conecta()
    {
        await using var site = await SiteTeste.CriarAsync();
        site.Bts.ChaveAssinatura = SiteTeste.ChaveEstranha;
        await AssertFalhaAsync(site);
    }

    [Fact]
    public async Task Id_token_de_outro_parceiro_nao_conecta()
    {
        await using var site = await SiteTeste.CriarAsync();
        site.Bts.Audiencia = "outro-parceiro";
        await AssertFalhaAsync(site);
    }

    private static async Task AssertFalhaAsync(SiteTeste site)
    {
        try
        {
            var (volta, cookies, _) = await EntrarAsync(site);
            Assert.DoesNotContain("__Host-bts-parceiro", cookies.Keys);
            Assert.NotEqual(HttpStatusCode.Redirect, volta.StatusCode);
        }
        catch (Exception e) when (e is not Xunit.Sdk.XunitException)
        {
            // O handler recusa o login com exceção (vira erro 500 no site): o importante é não conectar ninguém
        }
    }

    [Fact]
    public async Task Cancelar_na_bts_volta_ao_site_sem_erro()
    {
        await using var site = await SiteTeste.CriarAsync();
        var desafio = await site.Cliente.SendAsync(Get("/entrar/bts?retorno=%2Fcarrinho"));
        var q = QueryHelpers.ParseQuery(desafio.Headers.Location!.Query);
        var volta = await site.Cliente.SendAsync(Get(
            $"/signin-bts?error=access_denied&state={Uri.EscapeDataString(q["state"]!)}", Cookies(desafio)));

        Assert.Equal(HttpStatusCode.Redirect, volta.StatusCode);
        Assert.Equal("/carrinho", volta.Headers.Location!.OriginalString);
        Assert.DoesNotContain("__Host-bts-parceiro", Cookies(volta).Keys);
    }

    [Fact]
    public async Task Sair_sem_token_antifalsificacao_e_recusado()
    {
        await using var site = await SiteTeste.CriarAsync();
        var (_, cookies, _) = await EntrarAsync(site);
        var req = new HttpRequestMessage(HttpMethod.Post, "/sair/bts") { Content = new FormUrlEncodedContent([]) };
        req.Headers.Add("Cookie", string.Join("; ", cookies.Select(c => $"{c.Key}={c.Value}")));
        var r = await site.Cliente.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Sem_client_id_o_site_nao_sobe()
    {
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using var site = await SiteTeste.CriarAsync(o => o.ClientId = "");
        });
    }
}
