using System.Collections.Concurrent;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace Bts.Login.AspNetCore.Testes;

/// <summary>Contas do "parceiro" (em memória) e o login próprio dele (cookie "Proprio").</summary>
public sealed class ContasFalsas
{
    public ConcurrentDictionary<string, (string Email, string? Sub)> Contas { get; } = new();
    public List<string> Criadas { get; } = [];
}

public sealed class VinculoFalso(ContasFalsas contas) : IVinculoBts
{
    public Task<string?> ContaPorSubAsync(string sub, CancellationToken ct) =>
        Task.FromResult<string?>(contas.Contas.FirstOrDefault(c => c.Value.Sub == sub).Key);

    public Task<string?> ContaPorEmailAsync(string email, CancellationToken ct) =>
        Task.FromResult<string?>(contas.Contas.FirstOrDefault(c => string.Equals(c.Value.Email, email, StringComparison.OrdinalIgnoreCase)).Key);

    public Task VincularAsync(string conta, BtsPessoa pessoa, CancellationToken ct)
    {
        contas.Contas[conta] = (contas.Contas[conta].Email, pessoa.Id);
        return Task.CompletedTask;
    }

    public Task<string> CriarContaAsync(BtsPessoa pessoa, CancellationToken ct)
    {
        var id = "nova-" + contas.Criadas.Count;
        contas.Contas[id] = (pessoa.Email ?? "", pessoa.Id);
        contas.Criadas.Add(id);
        return Task.FromResult(id);
    }

    public async Task<string?> ContaAtualAsync(HttpContext ctx, CancellationToken ct)
    {
        var r = await ctx.AuthenticateAsync("Proprio");
        return r.Succeeded ? r.Principal.FindFirst("conta")?.Value : null;
    }
}

public partial class VinculoTests
{
    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]+)\"")]
    private static partial Regex TokenAf();

    private static Dictionary<string, string> Cookies(HttpResponseMessage r) =>
        (r.Headers.TryGetValues("Set-Cookie", out var v) ? v : [])
        .Select(c => c.Split(';')[0].Split('=', 2))
        .Where(p => p.Length == 2)
        .ToDictionary(p => p[0], p => p[1]);

    private static void Juntar(Dictionary<string, string> alvo, HttpResponseMessage r)
    {
        foreach (var c in Cookies(r))
            if (c.Value.Length == 0) alvo.Remove(c.Key); else alvo[c.Key] = c.Value;
    }

    private static HttpRequestMessage Pedido(HttpMethod m, string url, IDictionary<string, string> cookies, HttpContent? corpo = null)
    {
        var req = new HttpRequestMessage(m, url) { Content = corpo };
        if (cookies.Count > 0) req.Headers.Add("Cookie", string.Join("; ", cookies.Select(c => $"{c.Key}={c.Value}")));
        return req;
    }

    private static async Task<SiteTeste> SiteAsync(ContasFalsas contas, bool automatico = false, TimeSpan? validade = null) =>
        await SiteTeste.CriarAsync(extra: (auth, s) =>
        {
            s.AddSingleton(contas);
            auth.AddCookie("Proprio", o => { o.Cookie.Name = "proprio"; o.LoginPath = "/login-proprio"; });
            auth.AddVinculoBts<VinculoFalso>(o =>
            {
                o.CaminhoLoginProprio = "/login-proprio";
                o.NomeSite = "Parceiro Teste";
                o.VinculoAutomatico = automatico;
                if (validade is not null) o.Validade = validade.Value;
            });
        }, rotas: e =>
        {
            // O login antigo do parceiro (senha, Google…), simulado: entra direto na conta pedida
            e.MapGet("/login-proprio", async (HttpContext ctx, string conta, string? ReturnUrl) =>
            {
                await ctx.SignInAsync("Proprio", new ClaimsPrincipal(new ClaimsIdentity([new Claim("conta", conta)], "Proprio")));
                return Results.Redirect(ReturnUrl ?? "/");
            }).AllowAnonymous();
        });

    /// <summary>Clica em "Entrar com BTS" e volta da BTS com um código.</summary>
    private static async Task<HttpResponseMessage> EntrarComBtsAsync(SiteTeste site, Dictionary<string, string> cookies,
        string entrar = "/entrar/bts?retorno=%2Fpainel")
    {
        var desafio = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, entrar, cookies));
        Assert.Equal(HttpStatusCode.Redirect, desafio.StatusCode);
        Juntar(cookies, desafio);
        var q = QueryHelpers.ParseQuery(desafio.Headers.Location!.Query);
        site.Bts.Nonce = q["nonce"];
        var volta = await site.Cliente.SendAsync(Pedido(HttpMethod.Get,
            $"/signin-bts?code=c&state={Uri.EscapeDataString(q["state"]!)}&iss={Uri.EscapeDataString(SiteTeste.Emissor)}", cookies));
        Juntar(cookies, volta);
        return volta;
    }

    private static async Task<JsonElement> EuAsync(SiteTeste site, Dictionary<string, string> cookies)
    {
        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/eu", cookies));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;
    }

    private static async Task<HttpResponseMessage> LoginProprioAsync(SiteTeste site, Dictionary<string, string> cookies, string conta,
        string retorno = "/vincular/bts/concluir")
    {
        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get,
            $"/login-proprio?conta={conta}&ReturnUrl={Uri.EscapeDataString(retorno)}", cookies));
        Juntar(cookies, r);
        return r;
    }

    private static async Task<HttpResponseMessage> PostarAsync(SiteTeste site, Dictionary<string, string> cookies, string url,
        string? token)
    {
        var campos = token is null ? [] : new Dictionary<string, string> { ["__RequestVerificationToken"] = token };
        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Post, url, cookies, new FormUrlEncodedContent(campos)));
        Juntar(cookies, r);
        return r;
    }

    // ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Conta_ja_ligada_entra_direto()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", "sub-do-parceiro");
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();

        var volta = await EntrarComBtsAsync(site, cookies);

        Assert.Equal("/painel", volta.Headers.Location!.OriginalString);
        Assert.Equal("c1", (await EuAsync(site, cookies)).GetProperty("conta").GetString());
        Assert.Empty(contas.Criadas);
    }

    [Fact]
    public async Task Pessoa_nova_ganha_conta_nova_ja_ligada()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("outra@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();

        await EntrarComBtsAsync(site, cookies);

        Assert.Equal("nova-0", (await EuAsync(site, cookies)).GetProperty("conta").GetString());
        Assert.Equal("sub-do-parceiro", contas.Contas["nova-0"].Sub);
        Assert.Null(contas.Contas["c1"].Sub);
    }

    [Fact]
    public async Task Mesmo_email_nao_liga_sozinho_e_pede_o_login_antigo()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("MARIA@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();

        var volta = await EntrarComBtsAsync(site, cookies);

        Assert.Equal("/vincular/bts", volta.Headers.Location!.OriginalString);
        Assert.Null(contas.Contas["c1"].Sub);
        Assert.Empty(contas.Criadas);
        Assert.DoesNotContain("__Host-bts-parceiro", cookies.Keys); // ninguém conectado ainda
        Assert.Contains(VinculoBtsNomes.Cookie, cookies.Keys);

        var pagina = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts", cookies));
        var html = await pagina.Content.ReadAsStringAsync();
        Assert.Contains("m***@teste.com", html);   // e-mail mascarado
        Assert.DoesNotContain("maria@", html);
        Assert.Contains("/login-proprio?ReturnUrl=%2Fvincular%2Fbts%2Fconcluir", html);
        Assert.DoesNotContain("<script", html);
    }

    [Fact]
    public async Task Depois_do_login_antigo_e_da_confirmacao_as_contas_ficam_ligadas()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();
        await EntrarComBtsAsync(site, cookies);

        var login = await LoginProprioAsync(site, cookies, "c1");
        Assert.Equal("/vincular/bts/concluir", login.Headers.Location!.OriginalString);
        var confirmar = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts/concluir", cookies));
        Juntar(cookies, confirmar);
        Assert.Equal(HttpStatusCode.OK, confirmar.StatusCode);
        Assert.Null(contas.Contas["c1"].Sub); // só liga depois de confirmar

        var r = await PostarAsync(site, cookies, "/vincular/bts/concluir", TokenAf().Match(await confirmar.Content.ReadAsStringAsync()).Groups[1].Value);

        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("/painel", r.Headers.Location!.OriginalString);
        Assert.Equal("sub-do-parceiro", contas.Contas["c1"].Sub);
        Assert.DoesNotContain(VinculoBtsNomes.Cookie, cookies.Keys); // pendência apagada
        var eu = await EuAsync(site, cookies);
        Assert.Equal("c1", eu.GetProperty("conta").GetString());
        Assert.Equal([1, 3], eu.GetProperty("niveis").EnumerateArray().Select(e => e.GetInt32()));

        // Da próxima vez, entra direto
        var outra = new Dictionary<string, string>();
        await EntrarComBtsAsync(site, outra);
        Assert.Equal("c1", (await EuAsync(site, outra)).GetProperty("conta").GetString());
    }

    [Fact]
    public async Task Confirmar_sem_token_antifalsificacao_nao_liga()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();
        await EntrarComBtsAsync(site, cookies);
        await LoginProprioAsync(site, cookies, "c1");

        var r = await PostarAsync(site, cookies, "/vincular/bts/concluir", null);

        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Null(contas.Contas["c1"].Sub);
    }

    [Fact]
    public async Task Login_antigo_em_outra_conta_nao_liga()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        contas.Contas["c2"] = ("joao@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();
        await EntrarComBtsAsync(site, cookies);
        await LoginProprioAsync(site, cookies, "c2");

        var pagina = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts/concluir", cookies));
        Assert.Equal(HttpStatusCode.Conflict, pagina.StatusCode);

        // Mesmo forçando o envio, não liga
        var af = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts", cookies));
        Juntar(cookies, af);
        var token = TokenAf().Match(await af.Content.ReadAsStringAsync()).Groups[1].Value;
        var r = await PostarAsync(site, cookies, "/vincular/bts/concluir", token);
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Null(contas.Contas["c1"].Sub);
        Assert.Null(contas.Contas["c2"].Sub);
    }

    [Fact]
    public async Task Sem_a_pendencia_concluir_nao_faz_nada()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();
        await LoginProprioAsync(site, cookies, "c1", "/");

        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts/concluir", cookies));
        Assert.Equal("/", r.Headers.Location!.OriginalString);

        // Cookie adulterado também não vale
        cookies[VinculoBtsNomes.Cookie] = "CfDJ8adulterado";
        r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts/concluir", cookies));
        Assert.Equal("/", r.Headers.Location!.OriginalString);
        Assert.Null(contas.Contas["c1"].Sub);
    }

    [Fact]
    public async Task Pendencia_vencida_nao_vale()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        await using var site = await SiteAsync(contas, validade: TimeSpan.FromMilliseconds(300));
        var cookies = new Dictionary<string, string>();
        await EntrarComBtsAsync(site, cookies);
        await LoginProprioAsync(site, cookies, "c1");
        await Task.Delay(600);

        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts/concluir", cookies));
        Assert.Equal("/", r.Headers.Location!.OriginalString);
        Assert.Null(contas.Contas["c1"].Sub);
    }

    [Fact]
    public async Task Agora_nao_apaga_a_pendencia()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();
        await EntrarComBtsAsync(site, cookies);
        var pagina = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts", cookies));
        Juntar(cookies, pagina);

        var r = await PostarAsync(site, cookies, "/vincular/bts/cancelar", TokenAf().Match(await pagina.Content.ReadAsStringAsync()).Groups[1].Value);

        Assert.Equal("/", r.Headers.Location!.OriginalString);
        Assert.DoesNotContain(VinculoBtsNomes.Cookie, cookies.Keys);
        Assert.Null(contas.Contas["c1"].Sub);
    }

    [Fact]
    public async Task Email_nao_confirmado_nao_procura_conta_por_email()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        await using var site = await SiteAsync(contas);
        site.Bts.EmailConfirmado = false;
        var cookies = new Dictionary<string, string>();

        var volta = await EntrarComBtsAsync(site, cookies);

        Assert.Equal("/painel", volta.Headers.Location!.OriginalString);
        Assert.Null(contas.Contas["c1"].Sub);
        Assert.Single(contas.Criadas);
    }

    [Fact]
    public async Task Vinculo_automatico_liga_pelo_email_quando_ligado()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", null);
        await using var site = await SiteAsync(contas, automatico: true);
        var cookies = new Dictionary<string, string>();

        var volta = await EntrarComBtsAsync(site, cookies);

        Assert.Equal("/painel", volta.Headers.Location!.OriginalString);
        Assert.Equal("sub-do-parceiro", contas.Contas["c1"].Sub);
        Assert.Equal("c1", (await EuAsync(site, cookies)).GetProperty("conta").GetString());
    }

    [Fact]
    public async Task Quem_esta_conectado_liga_a_conta_bts_mesmo_com_email_diferente()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria.antigo@outro.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();
        await LoginProprioAsync(site, cookies, "c1", "/");

        var volta = await EntrarComBtsAsync(site, cookies, "/vincular/bts/iniciar?retorno=%2Fperfil");

        Assert.Equal("/perfil", volta.Headers.Location!.OriginalString);
        Assert.Equal("sub-do-parceiro", contas.Contas["c1"].Sub);
        Assert.Empty(contas.Criadas);
    }

    [Fact]
    public async Task Conta_bts_ligada_a_outra_conta_nao_e_tomada()
    {
        var contas = new ContasFalsas();
        contas.Contas["c1"] = ("maria@teste.com", "sub-do-parceiro");
        contas.Contas["c2"] = ("intruso@teste.com", null);
        await using var site = await SiteAsync(contas);
        var cookies = new Dictionary<string, string>();
        await LoginProprioAsync(site, cookies, "c2", "/");

        var volta = await EntrarComBtsAsync(site, cookies, "/vincular/bts/iniciar");

        Assert.Equal(HttpStatusCode.Conflict, volta.StatusCode);
        Assert.Null(contas.Contas["c2"].Sub);
        Assert.Equal("sub-do-parceiro", contas.Contas["c1"].Sub);
    }

    [Fact]
    public async Task Iniciar_sem_estar_conectado_manda_para_o_login_antigo()
    {
        var contas = new ContasFalsas();
        await using var site = await SiteAsync(contas);
        var r = await site.Cliente.SendAsync(Pedido(HttpMethod.Get, "/vincular/bts/iniciar", new Dictionary<string, string>()));
        Assert.Equal("/login-proprio?ReturnUrl=%2Fvincular%2Fbts%2Finiciar", r.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("maria@teste.com", "m***@teste.com")]
    [InlineData("ab@x.com", "a***@x.com")]
    [InlineData("a@x.com", "a***@x.com")]
    [InlineData("semarroba", "***")]
    public void Email_mascarado(string email, string esperado) => Assert.Equal(esperado, VinculoBtsNomes.Mascarar(email));

    [Fact]
    public async Task Sem_caminho_do_login_proprio_o_site_nao_sobe()
    {
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using var site = await SiteTeste.CriarAsync(extra: (auth, s) =>
            {
                s.AddSingleton(new ContasFalsas());
                auth.AddVinculoBts<VinculoFalso>(_ => { });
            });
        });
    }
}

/// <summary>Acesso aos internos usados nos testes.</summary>
internal static class VinculoBtsNomes
{
    public const string Cookie = "__Host-bts-vinculo";
    public static string Mascarar(string e) => VinculoBts.Mascarar(e);
}
