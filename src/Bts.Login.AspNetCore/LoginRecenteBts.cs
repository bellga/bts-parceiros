using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Bts.Login.AspNetCore;

/// <summary>
/// Exige que a pessoa tenha entrado na BTS há pouco tempo (e, opcionalmente, com a senha da BTS) — para ações
/// sensíveis como trocar a conta de recebimento. Confere o <c>auth_time</c> do token no servidor.
/// </summary>
public sealed class LoginRecenteBtsRequisito(TimeSpan limite, bool exigirSenha)
    : AuthorizationHandler<LoginRecenteBtsRequisito>, IAuthorizationRequirement
{
    public TimeSpan Limite { get; } = limite >= TimeSpan.Zero
        ? limite
        : throw new ArgumentOutOfRangeException(nameof(limite), "Bts: o limite do login recente não pode ser negativo.");

    /// <summary>Além de recente, o login precisa ter sido com a senha da BTS (<c>amr</c> com <c>pwd</c>).</summary>
    public bool ExigirSenha { get; } = exigirSenha;

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, LoginRecenteBtsRequisito requisito)
    {
        if (context.User.Identity?.IsAuthenticated != true) return Task.CompletedTask; // sem login: o desafio normal
        var relogio = (context.Resource as HttpContext)?.RequestServices.GetService<TimeProvider>();
        if (context.User.LoginRecenteBts(Limite, ExigirSenha, relogio)) context.Succeed(requisito);
        else context.Fail(new LoginAntigoBts(this));
        return Task.CompletedTask;
    }
}

/// <summary>Motivo da recusa: o login é antigo demais (ou não foi com a senha) para esta ação.</summary>
public sealed class LoginAntigoBts(LoginRecenteBtsRequisito requisito)
    : AuthorizationFailureReason(requisito, "Login antigo demais para esta ação.")
{
    public TimeSpan Limite => requisito.Limite;
    public bool ExigirSenha => requisito.ExigirSenha;
}

/// <summary>
/// Quando a recusa é por login antigo: na API (Bearer) responde 401 com
/// <c>WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=...</c> (RFC 9470), para o app
/// pedir o login de novo; no site (GET) leva a pessoa para a BTS com <c>max_age</c> (e <c>prompt=login</c> quando
/// exige a senha) e volta para a mesma página. Fora isso, o comportamento padrão do ASP.NET Core.
/// </summary>
internal sealed class BtsResultadoAutorizacao : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _padrao = new();

    public static void Registrar(IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(IAuthorizationMiddlewareResultHandler) &&
                              d.ImplementationType == typeof(BtsResultadoAutorizacao))) return;
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, BtsResultadoAutorizacao>();
    }

    public async Task HandleAsync(RequestDelegate next, HttpContext ctx, AuthorizationPolicy policy,
        PolicyAuthorizationResult resultado)
    {
        if (resultado.Forbidden &&
            resultado.AuthorizationFailure?.FailureReasons.OfType<LoginAntigoBts>().FirstOrDefault() is { } antigo)
        {
            var segundos = ((long)antigo.Limite.TotalSeconds).ToString(CultureInfo.InvariantCulture);
            if (ctx.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var descricao = antigo.ExigirSenha
                    ? "Entre de novo na BTS com a senha para continuar."
                    : "Entre de novo na BTS para continuar.";
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                ctx.Response.Headers.WWWAuthenticate =
                    $"Bearer error=\"{BtsPadroes.ErroLoginRecente}\", error_description=\"{descricao}\", max_age={segundos}";
                return;
            }
            var esquemas = ctx.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            if (HttpMethods.IsGet(ctx.Request.Method) && await esquemas.GetSchemeAsync(BtsPadroes.Esquema) is not null)
            {
                await ctx.ChallengeAsync(BtsPadroes.Esquema, new OpenIdConnectChallengeProperties
                {
                    RedirectUri = BtsExtensions.SoLocal($"{ctx.Request.PathBase}{ctx.Request.Path}{ctx.Request.QueryString}"),
                    MaxAge = antigo.Limite,
                    // Com a sessão da BTS ainda nova, o max_age sozinho volta direto; exigindo a senha, mostra a tela
                    Prompt = antigo.ExigirSenha ? OpenIdConnectPrompt.Login : null
                });
                return;
            }
        }
        await _padrao.HandleAsync(next, ctx, policy, resultado);
    }
}
