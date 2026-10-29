using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Bts.Login.AspNetCore;

public static class VinculoBtsExtensions
{
    /// <summary>
    /// Liga as pessoas da BTS às contas que o seu sistema já tem (veja <see cref="IVinculoBts"/>).
    /// Use depois de <c>AddEntrarComBts</c> ou <c>AddBts</c>; as rotas vêm com <c>MapEntrarComBts</c>.
    /// </summary>
    public static AuthenticationBuilder AddVinculoBts<T>(this AuthenticationBuilder builder, Action<VinculoBtsOptions> configurar)
        where T : class, IVinculoBts
    {
        builder.Services.AddScoped<IVinculoBts, T>();
        builder.Services.AddOptions<VinculoBtsOptions>().Configure(configurar)
            .Validate(o => { o.Validar(); return true; }).ValidateOnStart();
        builder.Services.AddDataProtection();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddOptions<OpenIdConnectOptions>(BtsPadroes.Esquema).PostConfigure(o =>
        {
            var anterior = o.Events.OnTicketReceived;
            o.Events.OnTicketReceived = async ctx =>
            {
                await anterior(ctx);
                if (ctx.Result is null || !ctx.Result.Handled) await VinculoBts.AoEntrarAsync(ctx);
            };
        });
        return builder;
    }
}

/// <summary>O fluxo do vínculo: decisão na volta da BTS, cookie de pendência e as páginas.</summary>
internal static class VinculoBts
{
    internal const string NomeCookie = "__Host-bts-vinculo";
    internal const string ItemVincularLogado = "bts.vincular";
    private const string Proposito = "Bts.Login.Vinculo.v1";

    private sealed record Pendencia(string Sub, string? Nome, string? Email, bool EmailConfirmado, string? Celular,
        int[] Niveis, string Conta, string Retorno, DateTimeOffset ExpiraEm)
    {
        public BtsPessoa Pessoa => new(Sub, Nome, Email, EmailConfirmado, Celular, Niveis);
    }

    // ── Volta da BTS ──────────────────────────────────────────────────────

    internal static async Task AoEntrarAsync(TicketReceivedContext ctx)
    {
        var http = ctx.HttpContext;
        var ct = http.RequestAborted;
        var vinculo = http.RequestServices.GetRequiredService<IVinculoBts>();
        var opcoes = http.RequestServices.GetRequiredService<IOptions<VinculoBtsOptions>>().Value;
        var pessoa = BtsPessoa.De(ctx.Principal!);
        var retorno = BtsExtensions.SoLocal(ctx.ReturnUri);
        var ligada = await vinculo.ContaPorSubAsync(pessoa.Id, ct);

        // "Vincular conta BTS" pedido por quem já está conectado no seu login
        if (ctx.Properties?.Items.ContainsKey(ItemVincularLogado) == true)
        {
            var atual = await vinculo.ContaAtualAsync(http, ct);
            if (atual is null)
            {
                await EncerrarAsync(ctx, Pagina(opcoes, "Entre primeiro", "<p>Entre na sua conta para ligar a conta BTS.</p>", 401));
                return;
            }
            if (ligada is not null && ligada != atual)
            {
                await EncerrarAsync(ctx, Pagina(opcoes, "Conta BTS já ligada",
                    "<p>Esta conta BTS já está ligada a outra conta aqui. Entre nela, ou use outra conta BTS.</p>", 409));
                return;
            }
            if (ligada is null) await vinculo.VincularAsync(atual, pessoa, ct);
            await ConcluirAsync(ctx, vinculo, atual, pessoa, retorno);
            return;
        }

        if (ligada is not null)
        {
            await ConcluirAsync(ctx, vinculo, ligada, pessoa, retorno);
            return;
        }

        var porEmail = pessoa.EmailConfirmado && !string.IsNullOrWhiteSpace(pessoa.Email)
            ? await vinculo.ContaPorEmailAsync(pessoa.Email!, ct)
            : null;
        if (porEmail is not null)
        {
            if (opcoes.VinculoAutomatico)
            {
                await vinculo.VincularAsync(porEmail, pessoa, ct);
                await ConcluirAsync(ctx, vinculo, porEmail, pessoa, retorno);
                return;
            }
            // Nunca junta só pelo e-mail: guarda a identidade da BTS e pede o login antigo uma vez
            var relogio = http.RequestServices.GetRequiredService<TimeProvider>();
            GravarPendencia(http, opcoes, relogio, new Pendencia(pessoa.Id, pessoa.Nome, pessoa.Email, pessoa.EmailConfirmado,
                pessoa.Celular, [.. pessoa.Niveis], porEmail, retorno, relogio.GetUtcNow().Add(opcoes.Validade)));
            ctx.Response.Redirect(opcoes.Caminho);
            ctx.HandleResponse();
            return;
        }

        var nova = await vinculo.CriarContaAsync(pessoa, ct);
        await ConcluirAsync(ctx, vinculo, nova, pessoa, retorno);
    }

    private static async Task ConcluirAsync(TicketReceivedContext ctx, IVinculoBts vinculo, string conta, BtsPessoa pessoa,
        string retorno)
    {
        if (await vinculo.EntrarAsync(ctx.HttpContext, conta, pessoa, ctx.HttpContext.RequestAborted))
        {
            ctx.Response.Redirect(retorno);
            ctx.HandleResponse();
            return;
        }
        // Segue o login normal do pacote, agora com a conta do parceiro na sessão
        ((ClaimsIdentity)ctx.Principal!.Identity!).AddClaim(new Claim(BtsClaims.Conta, conta));
    }

    private static async Task EncerrarAsync(TicketReceivedContext ctx, (int Status, string Html) pagina)
    {
        ctx.HandleResponse();
        ctx.Response.StatusCode = pagina.Status;
        ctx.Response.ContentType = "text/html; charset=utf-8";
        await ctx.Response.WriteAsync(pagina.Html, ctx.HttpContext.RequestAborted);
    }

    // ── Rotas ────────────────────────────────────────────────────────────

    internal static void Mapear(IEndpointRouteBuilder app, BtsLoginOptions bts)
    {
        var opcoes = app.ServiceProvider.GetRequiredService<IOptions<VinculoBtsOptions>>().Value;
        var g = app.MapGroup(opcoes.Caminho).AllowAnonymous();

        // Explica e manda para o login antigo
        g.MapGet("/", (HttpContext ctx, TimeProvider relogio) =>
        {
            var p = LerPendencia(ctx, relogio);
            if (p is null) return Results.Redirect("/");
            var voltar = $"{opcoes.Caminho}/concluir";
            var login = $"{opcoes.CaminhoLoginProprio}?{Uri.EscapeDataString(opcoes.ParametroRetorno)}={Uri.EscapeDataString(voltar)}";
            return Html(Pagina(opcoes, "Você já tem uma conta aqui",
                $"<p>Já existe uma conta em {Cod(opcoes.NomeSite)} com o e-mail <strong>{Cod(Mascarar(p.Email))}</strong>.</p>" +
                "<p>Para ligar essa conta à sua conta BTS, entre <strong>uma vez</strong> do jeito de sempre. " +
                "Depois disso, você pode entrar com qualquer um dos dois.</p>" +
                $"<p><a href=\"{Cod(login)}\">Entrar do jeito de sempre</a></p>" +
                Cancelar(ctx, opcoes)));
        });

        // Já entrou do jeito antigo: confirma
        g.MapGet("/concluir", async (HttpContext ctx, IVinculoBts vinculo, TimeProvider relogio, IAntiforgery af) =>
        {
            var p = LerPendencia(ctx, relogio);
            if (p is null) return Results.Redirect("/");
            var atual = await vinculo.ContaAtualAsync(ctx, ctx.RequestAborted);
            if (atual is null) return Results.Redirect(opcoes.Caminho);
            if (atual != p.Conta) return Html(ContaDiferente(ctx, opcoes));
            var token = af.GetAndStoreTokens(ctx);
            return Html(Pagina(opcoes, "Ligar as contas",
                $"<p>Ligar a sua conta BTS (<strong>{Cod(Mascarar(p.Email))}</strong>) a esta conta?</p>" +
                $"<form method=\"post\" action=\"{Cod(opcoes.Caminho)}/concluir\">" +
                $"<input type=\"hidden\" name=\"{Cod(token.FormFieldName)}\" value=\"{Cod(token.RequestToken)}\">" +
                "<button type=\"submit\">Ligar e continuar</button></form>" + Cancelar(ctx, opcoes)));
        });

        g.MapPost("/concluir", async (HttpContext ctx, IVinculoBts vinculo, TimeProvider relogio, IAntiforgery af) =>
        {
            if (!await af.IsRequestValidAsync(ctx)) return Results.BadRequest();
            var p = LerPendencia(ctx, relogio);
            if (p is null) return Results.Redirect("/");
            var ct = ctx.RequestAborted;
            var atual = await vinculo.ContaAtualAsync(ctx, ct);
            if (atual is null) return Results.Redirect(opcoes.Caminho);
            if (atual != p.Conta) return Html(ContaDiferente(ctx, opcoes));
            var ligada = await vinculo.ContaPorSubAsync(p.Sub, ct);
            if (ligada is not null && ligada != atual)
                return Html(Pagina(opcoes, "Conta BTS já ligada",
                    "<p>Esta conta BTS já está ligada a outra conta aqui.</p>", 409));
            if (ligada is null) await vinculo.VincularAsync(atual, p.Pessoa, ct);
            ApagarPendencia(ctx);
            if (!await vinculo.EntrarAsync(ctx, atual, p.Pessoa, ct))
            {
                var esquema = ctx.RequestServices.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                    .Get(BtsPadroes.Esquema).SignInScheme;
                await ctx.SignInAsync(esquema, Sessao(p.Pessoa, atual));
            }
            return Results.Redirect(p.Retorno);
        }).DisableAntiforgery(); // conferido acima

        g.MapPost("/cancelar", async (HttpContext ctx, IAntiforgery af) =>
        {
            if (!await af.IsRequestValidAsync(ctx)) return Results.BadRequest();
            ApagarPendencia(ctx);
            return Results.Redirect("/");
        }).DisableAntiforgery();

        // Quem já está conectado no seu login liga a conta BTS (também serve quando os e-mails são diferentes)
        g.MapGet("/iniciar", async (HttpContext ctx, IVinculoBts vinculo, string? retorno) =>
        {
            if (await vinculo.ContaAtualAsync(ctx, ctx.RequestAborted) is null)
                return Results.Redirect(
                    $"{opcoes.CaminhoLoginProprio}?{Uri.EscapeDataString(opcoes.ParametroRetorno)}={Uri.EscapeDataString(opcoes.Caminho + "/iniciar")}");
            var props = new AuthenticationProperties { RedirectUri = BtsExtensions.SoLocal(retorno) };
            props.Items[ItemVincularLogado] = "1";
            return Results.Challenge(props, [BtsPadroes.Esquema]);
        });
    }

    private static ClaimsPrincipal Sessao(BtsPessoa p, string conta)
    {
        var id = new ClaimsIdentity("Bts", BtsClaims.Nome, "role");
        id.AddClaim(new Claim(BtsClaims.Id, p.Id));
        id.AddClaim(new Claim(BtsClaims.Conta, conta));
        if (p.Nome is not null) id.AddClaim(new Claim(BtsClaims.Nome, p.Nome));
        if (p.Email is not null) id.AddClaim(new Claim(BtsClaims.Email, p.Email));
        if (p.EmailConfirmado) id.AddClaim(new Claim(BtsClaims.EmailConfirmado, "true"));
        if (p.Celular is not null) id.AddClaim(new Claim(BtsClaims.Celular, p.Celular));
        foreach (var n in p.Niveis) id.AddClaim(new Claim(BtsClaims.Niveis, n.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return new ClaimsPrincipal(id);
    }

    // ── Pendência (cookie cifrado e com prazo) ───────────────────────────

    private static IDataProtector Protetor(HttpContext ctx) =>
        ctx.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(Proposito);

    private static void GravarPendencia(HttpContext ctx, VinculoBtsOptions opcoes, TimeProvider relogio, Pendencia p)
    {
        var valor = Protetor(ctx).Protect(JsonSerializer.Serialize(p));
        ctx.Response.Cookies.Append(NomeCookie, valor, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax, // a pessoa volta do login antigo por navegação
            Path = "/",
            Expires = relogio.GetUtcNow().Add(opcoes.Validade),
            IsEssential = true
        });
    }

    private static Pendencia? LerPendencia(HttpContext ctx, TimeProvider relogio)
    {
        if (!ctx.Request.Cookies.TryGetValue(NomeCookie, out var valor) || string.IsNullOrEmpty(valor)) return null;
        try
        {
            var p = JsonSerializer.Deserialize<Pendencia>(Protetor(ctx).Unprotect(valor));
            // O prazo vale mesmo que o navegador não apague o cookie
            return p is not null && p.ExpiraEm > relogio.GetUtcNow() ? p : null;
        }
        catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or JsonException)
        {
            return null; // adulterado ou de outra instalação
        }
    }

    private static void ApagarPendencia(HttpContext ctx) =>
        ctx.Response.Cookies.Delete(NomeCookie, new CookieOptions { Path = "/", Secure = true, HttpOnly = true, SameSite = SameSiteMode.Lax });

    // ── Páginas (HTML simples, sem script e sem estilo inline: funciona com qualquer CSP) ─────

    private static string Cod(string? s) => WebUtility.HtmlEncode(s ?? "");

    internal static string Mascarar(string? email)
    {
        if (string.IsNullOrEmpty(email)) return "";
        var arroba = email.IndexOf('@');
        if (arroba <= 0) return "***";
        return email[0] + "***" + email[arroba..]; // tamanho fixo: não revela o comprimento do nome
    }

    private static string Cancelar(HttpContext ctx, VinculoBtsOptions opcoes)
    {
        var token = ctx.RequestServices.GetRequiredService<IAntiforgery>().GetAndStoreTokens(ctx);
        return $"<form method=\"post\" action=\"{Cod(opcoes.Caminho)}/cancelar\">" +
               $"<input type=\"hidden\" name=\"{Cod(token.FormFieldName)}\" value=\"{Cod(token.RequestToken)}\">" +
               "<button type=\"submit\">Agora não</button></form>";
    }

    private static (int, string) ContaDiferente(HttpContext ctx, VinculoBtsOptions opcoes) =>
        Pagina(opcoes, "Outra conta",
            "<p>Você entrou numa conta diferente da que tem o mesmo e-mail da sua conta BTS. Saia e entre na conta certa, " +
            "ou desista de ligar.</p>" + Cancelar(ctx, opcoes), 409);

    private static (int Status, string Html) Pagina(VinculoBtsOptions opcoes, string titulo, string corpo, int status = 200) =>
        (status, "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">" +
                 "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                 $"<title>{Cod(titulo)} · {Cod(opcoes.NomeSite)}</title></head><body><main>" +
                 $"<h1>{Cod(titulo)}</h1>{corpo}</main></body></html>");

    private static IResult Html((int Status, string Html) p) =>
        Results.Content(p.Html, "text/html; charset=utf-8", statusCode: p.Status);
}
