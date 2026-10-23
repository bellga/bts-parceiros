using System.Net;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.Options;

namespace Bts.Login.AspNetCore;

public enum BtsTema { Escuro, Claro }
public enum BtsTexto { Entrar, Continuar }

/// <summary>
/// Botão oficial "Entrar com BTS" (https://bellga.tech/marca.html). É um link comum: não carrega script nenhum.
/// Inclua o CSS uma vez na página: <c>&lt;link rel="stylesheet" href="/_content/Bts.Login.AspNetCore/botao-bts.css"&gt;</c>.
/// </summary>
public static class BtsBotao
{
    /// <summary>Endereço do CSS do botão (arquivo estático do pacote).</summary>
    public const string CaminhoCss = "/_content/Bts.Login.AspNetCore/botao-bts.css";

    private const string Escudo =
        "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\">" +
        "<path d=\"M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z\"/><path d=\"M9 12l2 2 4-4\"/></svg>";

    public static string Rotulo(BtsTexto texto) => texto == BtsTexto.Continuar ? "Continuar com BTS" : "Entrar com BTS";

    /// <summary>HTML do botão (para páginas sem Razor).</summary>
    public static HtmlString Html(string href, BtsTema tema = BtsTema.Escuro, BtsTexto texto = BtsTexto.Entrar,
        bool soIcone = false) => new(Montar(href, tema, texto, soIcone));

    /// <summary>Endereço do botão: a rota de entrar do site, com o retorno (só caminho local).</summary>
    public static string Endereco(string caminhoEntrar, string? retorno) =>
        string.IsNullOrEmpty(retorno) || BtsExtensions.SoLocal(retorno) == "/"
            ? caminhoEntrar
            : $"{caminhoEntrar}?retorno={Uri.EscapeDataString(retorno)}";

    internal static string Montar(string href, BtsTema tema, BtsTexto texto, bool soIcone)
    {
        var classeTema = tema == BtsTema.Claro ? "bts-claro" : "bts-escuro";
        var rotulo = Rotulo(texto);
        var link = WebUtility.HtmlEncode(href);
        return soIcone
            ? $"<a class=\"bts-botao bts-so-icone {classeTema}\" href=\"{link}\" aria-label=\"{rotulo}\"><span class=\"bts-icone\">{Escudo}</span></a>"
            : $"<a class=\"bts-botao {classeTema}\" href=\"{link}\"><span class=\"bts-icone\">{Escudo}</span><span>{rotulo}</span></a>";
    }
}

/// <summary>
/// <c>&lt;bts-botao /&gt;</c> nas páginas Razor (com <c>@addTagHelper *, Bts.Login.AspNetCore</c>).
/// Atributos: <c>tema="Claro"</c>, <c>texto="Continuar"</c>, <c>so-icone="true"</c>, <c>retorno="/caminho"</c>.
/// </summary>
[HtmlTargetElement("bts-botao", TagStructure = TagStructure.WithoutEndTag)]
public sealed class BtsBotaoTagHelper(IOptions<BtsLoginOptions> opcoes) : TagHelper
{
    public BtsTema Tema { get; set; } = BtsTema.Escuro;
    public BtsTexto Texto { get; set; } = BtsTexto.Entrar;
    public bool SoIcone { get; set; }
    public string? Retorno { get; set; }

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        output.TagName = null;
        output.Content.SetHtmlContent(BtsBotao.Montar(
            BtsBotao.Endereco(opcoes.Value.CaminhoEntrar, Retorno), Tema, Texto, SoIcone));
    }
}
