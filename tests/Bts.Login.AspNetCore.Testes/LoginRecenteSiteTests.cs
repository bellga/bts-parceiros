using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace Bts.Login.AspNetCore.Testes;

/// <summary>Site do parceiro: auth_time e amr na sessão, rota de pedir login de novo e política de login recente.</summary>
public class LoginRecenteSiteTests
{
    private static Dictionary<string, string> Cookies(HttpResponseMessage r) =>
        (r.Headers.TryGetValues("Set-Cookie", out var v) ? v : [])
        .Select(c => c.Split(';')[0].Split('=', 2))
        .Where(p => p.Length == 2 && p[1].Length > 0)
        .ToDictionary(p => p[0], p => p[1]);

    private static HttpRequestMessage Pedido(HttpMethod metodo, string url, IDictionary<string, string>? cookies = null)
    {
        var req = new HttpRequestMessage(metodo, url);
        if (cookies is { Count: > 0 }) req.Headers.Add("Cookie", string.Join("; ", cookies.Select(c => $"{c.Key}={c.Value}")));
        return req;
    }

    private static Task<SiteTeste> SiteAsync() => SiteTeste.CriarAsync(rotas: e =>
    {
        e.MapGet("/login", (ClaimsPrincipal u) =>
            $"{u.AutenticadoEmBts()?.ToUnixTimeSeconds()}|{string.Join(',', u.FormasDeEntrarBts())}").RequireAuthorization();
        e.MapGet("/sensivel", () => "ok").RequireAuthorization(p => p.ExigirLoginRecenteBts(TimeSpan.FromMinutes(5)));
        e.MapGet("/sensivel-senha", () => "ok")
            .RequireAuthorization(p => p.ExigirLoginRecenteBts(TimeSpan.FromMinutes(5), exigirSenha: true));
        e.MapPost("/sensivel", () => "ok").RequireAuthorization(p => p.ExigirLoginRecenteBts(TimeSpan.FromMinutes(5)));
    });

    /// <summary>Faz o login (o que a BTS falsa emite está em site.Bts) e devolve os cookies da sessão do site.</summary>
    private static async Task<(Dictionary<string, string> Cookies, HttpResponseMessage Volta)> EntrarAsync(SiteTeste site,
        string entrar = "/entrar/bts", Dictionary<string, string>? cookies = null)
    {
        var desafio = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, entrar, cookies));
        Assert.Equal(HttpStatusCode.Redirect, desafio.StatusCode);
        var q = QueryHelpers.ParseQuery(desafio.Headers.Location!.Query);
        site.Bts.Nonce = q["nonce"];
        var todos = new Dictionary<string, string>(cookies ?? []);
        foreach (var c in Cookies(desafio)) todos[c.Key] = c.Value;
        var volta = await site.Cliente.SendAsync(Pedido(HttpMethod.Get,
            $"/signin-bts?code=codigo-teste&state={Uri.EscapeDataString(q["state"]!)}&iss={Uri.EscapeDataString(SiteTeste.Emissor)}",
            todos));
        foreach (var c in Cookies(volta)) todos[c.Key] = c.Value;
        return (todos, volta);
    }

    [Fact]
    public async Task Sessao_do_site_guarda_auth_time_e_amr()
    {
        await using var site = await SiteAsync();
        var quando = DateTimeOffset.UtcNow.AddMinutes(-1);
        site.Bts.AutenticadoEm = quando;
        site.Bts.Formas = ["pwd", "otp", "mfa"];
        var (cookies, _) = await EntrarAsync(site);
        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/login", cookies));
        Assert.Equal($"{quando.ToUnixTimeSeconds()}|pwd,otp,mfa", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Rota_entrar_pede_a_senha_de_novo_e_max_age()
    {
        await using var site = await SiteAsync();
        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/entrar/bts?retorno=%2Fsensivel&senha=1&max_age=300"));
        var q = QueryHelpers.ParseQuery(r.Headers.Location!.Query);
        Assert.Equal("login", q["prompt"]);
        Assert.Equal("300", q["max_age"]);

        var simples = QueryHelpers.ParseQuery((await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/entrar/bts"))).Headers.Location!.Query);
        Assert.False(simples.ContainsKey("prompt"));
        Assert.False(simples.ContainsKey("max_age"));
    }

    [Fact]
    public async Task Pagina_sensivel_com_login_antigo_vai_para_a_bts_e_volta_para_ela()
    {
        await using var site = await SiteAsync();
        site.Bts.AutenticadoEm = DateTimeOffset.UtcNow.AddMinutes(-30);
        var (cookies, _) = await EntrarAsync(site);

        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/sensivel?x=1", cookies));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.StartsWith(SiteTeste.Emissor + "connect/authorize", r.Headers.Location!.ToString());
        var q = QueryHelpers.ParseQuery(r.Headers.Location.Query);
        Assert.Equal("300", q["max_age"]);
        Assert.False(q.ContainsKey("prompt")); // sem exigir senha: se a sessão da BTS for nova, volta direto

        // Entrou de novo agora: a página abre e a volta é para ela mesma
        site.Bts.AutenticadoEm = DateTimeOffset.UtcNow;
        site.Bts.Nonce = q["nonce"];
        foreach (var c in Cookies(r)) cookies[c.Key] = c.Value;
        var volta = await site.Cliente.SendAsync(Pedido(HttpMethod.Get,
            $"/signin-bts?code=codigo-teste&state={Uri.EscapeDataString(q["state"]!)}&iss={Uri.EscapeDataString(SiteTeste.Emissor)}",
            cookies));
        Assert.Equal("/sensivel?x=1", volta.Headers.Location!.OriginalString);
        foreach (var c in Cookies(volta)) cookies[c.Key] = c.Value;
        var ok = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/sensivel?x=1", cookies));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task Exigindo_senha_quem_entrou_pelo_google_ve_a_tela_de_login_da_bts()
    {
        await using var site = await SiteAsync();
        site.Bts.Formas = ["google"];
        var (cookies, _) = await EntrarAsync(site);
        Assert.Equal(HttpStatusCode.OK, (await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/sensivel", cookies))).StatusCode);

        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/sensivel-senha", cookies));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("login", QueryHelpers.ParseQuery(r.Headers.Location!.Query)["prompt"]); // nunca volta sozinha
    }

    [Fact]
    public async Task Post_sensivel_com_login_antigo_recebe_403()
    {
        await using var site = await SiteAsync();
        site.Bts.AutenticadoEm = DateTimeOffset.UtcNow.AddMinutes(-30);
        var (cookies, _) = await EntrarAsync(site);
        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Post, "/sensivel", cookies));
        Assert.NotEqual(HttpStatusCode.OK, r.StatusCode); // recusa padrão do cookie (POST não é levado para a BTS)
        Assert.False(r.Headers.Location?.ToString().StartsWith(SiteTeste.Emissor, StringComparison.Ordinal) ?? false);
    }
}
