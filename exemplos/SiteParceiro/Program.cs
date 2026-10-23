// Site de exemplo com "Entrar com BTS".
// Configure o ClientId e o segredo recebidos no cadastro (fora do código):
//   dotnet user-secrets set "Bts:ClientId" "meu-site"
//   dotnet user-secrets set "Bts:Segredo" "..."
// Cadastre na BTS: retorno https://SEU-SITE/signin-bts e saída https://SEU-SITE/signout-callback-bts
using System.Net;
using Bts.Login.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEntrarComBts(o =>
{
    o.ClientId = builder.Configuration["Bts:ClientId"] ?? "";
    o.Segredo = builder.Configuration["Bts:Segredo"];
    o.Escopos.Add(BtsEscopos.Celular);
    o.Escopos.Add(BtsEscopos.Niveis);
});
builder.Services.AddAuthorization(o => o.AddPolicy("celular-confirmado", p => p.ExigirNivelBts(3)));

var app = builder.Build();
app.UseHttpsRedirection();
app.MapStaticAssets(); // serve o CSS do botão (/_content/Bts.Login.AspNetCore/botao-bts.css)
app.UseAuthentication();
app.UseAuthorization();

app.MapEntrarComBts(); // GET /entrar/bts e POST /sair/bts

app.MapGet("/", (HttpContext ctx, IAntiforgery af) =>
{
    var u = ctx.User;
    string corpo;
    if (u.Identity?.IsAuthenticated == true)
    {
        var token = af.GetAndStoreTokens(ctx);
        corpo = $"""
            <h1>Olá, {WebUtility.HtmlEncode(u.NomeBts())}</h1>
            <p>E-mail: {WebUtility.HtmlEncode(u.EmailBts())}</p>
            <p>Celular: {WebUtility.HtmlEncode(u.CelularBts() ?? "não informado")}</p>
            <p>Níveis BTS: {string.Join(", ", u.NiveisBts())}</p>
            <p><a href="/area-celular">Área só para celular confirmado</a></p>
            <form method="post" action="/sair/bts">
              <input type="hidden" name="{token.FormFieldName}" value="{token.RequestToken}">
              <button>Sair</button>
            </form>
            """;
    }
    else
    {
        corpo = $"""
            <h1>Site de exemplo</h1>
            <p>{BtsBotao.Html(BtsBotao.Endereco("/entrar/bts", "/"))}</p>
            <p>{BtsBotao.Html("/entrar/bts", BtsTema.Claro, BtsTexto.Continuar)}</p>
            """;
    }
    return Results.Content($"""
        <!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Parceiro de exemplo</title>
        <link rel="stylesheet" href="{BtsBotao.CaminhoCss}">
        </head><body style="font-family:system-ui;max-width:560px;margin:40px auto;padding:0 16px">{corpo}</body></html>
        """, "text/html; charset=utf-8");
});

app.MapGet("/area-celular", (HttpContext ctx) => $"Celular confirmado: {ctx.User.CelularBts()}")
    .RequireAuthorization("celular-confirmado");

app.Run();
