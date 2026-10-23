using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Bts.Login.AspNetCore;

public static class BtsExtensions
{
    /// <summary>
    /// Site com login só pela BTS: cookie de sessão do site + login na BTS.
    /// Para usar junto com outro login (Google, senha própria…), use <see cref="AddBts"/> no seu AddAuthentication.
    /// </summary>
    public static AuthenticationBuilder AddEntrarComBts(this IServiceCollection services, Action<BtsLoginOptions> configurar)
    {
        var builder = services.AddAuthentication(o =>
            {
                o.DefaultScheme = BtsPadroes.EsquemaCookie;
                o.DefaultChallengeScheme = BtsPadroes.Esquema;
            })
            .AddCookie(BtsPadroes.EsquemaCookie, o =>
            {
                o.Cookie.Name = "__Host-bts-parceiro";
                o.Cookie.HttpOnly = true;
                o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                o.Cookie.SameSite = SameSiteMode.Lax; // a volta da BTS é uma navegação (GET)
                o.Cookie.Path = "/";
                o.SlidingExpiration = true;
                o.ExpireTimeSpan = TimeSpan.FromDays(14);
            });
        return builder.AddBts(configurar, BtsPadroes.EsquemaCookie);
    }

    /// <summary>Adiciona o login na BTS a uma configuração de autenticação existente.</summary>
    /// <param name="esquemaSessao">Esquema (cookie) onde a pessoa fica conectada depois do login.</param>
    public static AuthenticationBuilder AddBts(this AuthenticationBuilder builder, Action<BtsLoginOptions> configurar,
        string? esquemaSessao = null)
    {
        builder.Services.AddOptions<BtsLoginOptions>().Configure(configurar).Validate(o => { o.Validar(); return true; })
            .ValidateOnStart();
        builder.Services.AddAntiforgery();
        builder.Services.AddOptions<OpenIdConnectOptions>(BtsPadroes.Esquema)
            .Configure<IOptions<BtsLoginOptions>>((oidc, bts) => Configurar(oidc, bts.Value, esquemaSessao));
        return builder.AddOpenIdConnect(BtsPadroes.Esquema, BtsPadroes.NomeExibicao, _ => { });
    }

    internal static void Configurar(OpenIdConnectOptions o, BtsLoginOptions bts, string? esquemaSessao)
    {
        bts.Validar();
        o.Authority = bts.Emissor;
        o.ClientId = bts.ClientId;
        o.ClientSecret = string.IsNullOrEmpty(bts.Segredo) ? null : bts.Segredo;
        if (esquemaSessao is not null) o.SignInScheme = esquemaSessao;
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.ResponseMode = OpenIdConnectResponseMode.Query; // a BTS responde por redirecionamento (sem form_post)
        o.UsePkce = true;
        o.CallbackPath = bts.CaminhoRetorno;
        o.SignedOutCallbackPath = bts.CaminhoRetornoSaida;
        o.SignedOutRedirectUri = "/";
        o.RequireHttpsMetadata = new Uri(bts.Emissor).Scheme == Uri.UriSchemeHttps;
        o.SaveTokens = bts.GuardarTokens;
        o.GetClaimsFromUserInfoEndpoint = false; // o id_token já traz os dados dos escopos permitidos
        o.MapInboundClaims = false;              // claims com os nomes do OpenID Connect (sub, name, email…)
        o.TokenValidationParameters.NameClaimType = BtsClaims.Nome;
        o.TokenValidationParameters.RoleClaimType = "role";
        o.Scope.Clear();
        o.Scope.Add(BtsEscopos.OpenId);
        foreach (var e in bts.Escopos) o.Scope.Add(e);
        // Cancelar na tela da BTS volta com erro access_denied: leva a pessoa para o início, sem página de erro
        o.Events.OnAccessDenied = ctx =>
        {
            ctx.Response.Redirect(SoLocal(ctx.ReturnUrl));
            ctx.HandleResponse();
            return Task.CompletedTask;
        };
        o.Events.OnRemoteFailure = ctx =>
        {
            if (ctx.Failure?.Message.Contains("access_denied", StringComparison.Ordinal) == true)
            {
                ctx.Response.Redirect("/");
                ctx.HandleResponse();
            }
            return Task.CompletedTask;
        };
    }

    /// <summary>
    /// Valida os tokens que os apps do parceiro mandam para a API dele (Authorization: Bearer ...).
    /// </summary>
    public static AuthenticationBuilder AddBtsBearer(this AuthenticationBuilder builder, Action<BtsBearerOptions> configurar,
        string esquema = BtsPadroes.EsquemaBearer)
    {
        builder.Services.AddOptions<BtsBearerOptions>(esquema).Configure(configurar);
        builder.Services.AddOptions<JwtBearerOptions>(esquema)
            .Configure<IOptionsMonitor<BtsBearerOptions>>((jwt, bts) => Configurar(jwt, bts.Get(esquema)));
        return builder.AddJwtBearer(esquema, _ => { });
    }

    internal static void Configurar(JwtBearerOptions o, BtsBearerOptions bts)
    {
        if (bts.ClientIds.Count == 0)
            throw new InvalidOperationException("Bts: informe os ClientIds dos apps cujos tokens a API aceita.");
        o.Authority = bts.Emissor;
        o.RequireHttpsMetadata = new Uri(bts.Emissor).Scheme == Uri.UriSchemeHttps;
        o.MapInboundClaims = false;
        o.TokenValidationParameters.ValidIssuer = bts.Emissor;
        o.TokenValidationParameters.ValidAudiences = bts.ClientIds;
        o.TokenValidationParameters.ValidateAudience = true;
        o.TokenValidationParameters.NameClaimType = BtsClaims.Nome;
        o.TokenValidationParameters.ValidTypes = ["at+jwt"]; // só access token (um id_token não serve de chave)
    }

    /// <summary>
    /// Rotas do botão: GET <c>/entrar/bts?retorno=/caminho</c> (inicia o login) e POST <c>/sair/bts</c>
    /// (encerra a sessão no site e na BTS; mande o token antifalsificação no formulário).
    /// </summary>
    public static IEndpointConventionBuilder MapEntrarComBts(this IEndpointRouteBuilder app)
    {
        var bts = app.ServiceProvider.GetRequiredService<IOptions<BtsLoginOptions>>().Value;
        var grupo = app.MapGroup("");
        grupo.MapGet(bts.CaminhoEntrar, (string? retorno) =>
                Results.Challenge(new AuthenticationProperties { RedirectUri = SoLocal(retorno) }, [BtsPadroes.Esquema]))
            .AllowAnonymous();
        grupo.MapPost(bts.CaminhoSair, async (HttpContext ctx, IAntiforgery af) =>
        {
            if (!await af.IsRequestValidAsync(ctx)) return Results.BadRequest();
            var esquemaSessao = ctx.RequestServices.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                .Get(BtsPadroes.Esquema).SignInScheme;
            var esquemas = new List<string> { BtsPadroes.Esquema };
            if (!string.IsNullOrEmpty(esquemaSessao)) esquemas.Insert(0, esquemaSessao);
            else await ctx.SignOutAsync(); // esquema padrão do site
            return Results.SignOut(new AuthenticationProperties { RedirectUri = "/" }, esquemas);
        }).AllowAnonymous().DisableAntiforgery(); // conferido acima (funciona também sem MVC)
        return grupo;
    }

    /// <summary>Só caminhos do próprio site (evita redirecionamento aberto).</summary>
    internal static string SoLocal(string? retorno) =>
        !string.IsNullOrEmpty(retorno) && retorno.StartsWith('/') && !retorno.StartsWith("//", StringComparison.Ordinal)
        && !retorno.StartsWith("/\\", StringComparison.Ordinal) && !retorno.Any(char.IsControl)
            ? retorno
            : "/";

    /// <summary>Política que exige um nível de verificação da BTS (1 = e-mail, 3 = celular).</summary>
    public static AuthorizationPolicyBuilder ExigirNivelBts(this AuthorizationPolicyBuilder p, int nivel) =>
        p.RequireAuthenticatedUser().RequireAssertion(c => c.User.TemNivelBts(nivel));
}
