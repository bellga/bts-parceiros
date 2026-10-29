using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Bts.Login.AspNetCore;

/// <summary>A pessoa que entrou com a BTS (só os dados dos escopos que ela permitiu).</summary>
public sealed record BtsPessoa(
    string Id, string? Nome, string? Email, bool EmailConfirmado, string? Celular, IReadOnlyList<int> Niveis)
{
    public bool TemNivel(int nivel) => Niveis.Contains(nivel);

    internal static BtsPessoa De(ClaimsPrincipal u) => new(
        u.IdBts() ?? throw new InvalidOperationException("Login da BTS sem 'sub'."),
        u.NomeBts(),
        u.EmailBts(),
        string.Equals(u.FindFirst(BtsClaims.EmailConfirmado)?.Value, "true", StringComparison.OrdinalIgnoreCase),
        u.CelularBts(),
        [.. u.NiveisBts()]);
}

/// <summary>
/// Liga as pessoas da BTS às contas que o seu sistema já tem (de senha própria, Google, Facebook…).
/// Você implementa só o acesso às suas contas; o pacote faz o fluxo seguro:
/// <list type="number">
/// <item><c>sub</c> já ligado a uma conta → entra nela.</item>
/// <item>e-mail da BTS igual ao de uma conta sua → a pessoa entra <b>uma vez</b> do jeito de sempre para provar
/// que é dona da conta, confirma, e só então o <c>sub</c> é gravado (nunca junta contas só pelo e-mail).</item>
/// <item>nenhuma conta → <see cref="CriarContaAsync"/>.</item>
/// </list>
/// Registre com <c>AddVinculoBts&lt;SuaClasse&gt;()</c>. A classe é criada por pedido (scoped): pode receber o seu DbContext.
/// </summary>
public interface IVinculoBts
{
    /// <summary>Conta sua já ligada a este identificador da BTS (o <c>sub</c>), ou null.</summary>
    Task<string?> ContaPorSubAsync(string sub, CancellationToken ct);

    /// <summary>Conta sua com este e-mail (compare sem diferenciar maiúsculas), ou null.</summary>
    Task<string?> ContaPorEmailAsync(string email, CancellationToken ct);

    /// <summary>Grava o <c>sub</c> da BTS na conta (uma conta sua tem no máximo um <c>sub</c>).</summary>
    Task VincularAsync(string conta, BtsPessoa pessoa, CancellationToken ct);

    /// <summary>Cria uma conta nova, já ligada ao <c>sub</c>, e devolve o identificador dela.</summary>
    Task<string> CriarContaAsync(BtsPessoa pessoa, CancellationToken ct);

    /// <summary>Conta em que a pessoa está conectada pelo <b>seu</b> login (senha, Google…), ou null.</summary>
    Task<string?> ContaAtualAsync(HttpContext ctx, CancellationToken ct);

    /// <summary>
    /// Opcional: conecta a pessoa no seu próprio esquema (ex.: ASP.NET Identity) e devolve true.
    /// Devolvendo false (padrão), o pacote conecta no cookie da BTS, com a claim <see cref="BtsClaims.Conta"/>.
    /// </summary>
    Task<bool> EntrarAsync(HttpContext ctx, string conta, BtsPessoa pessoa, CancellationToken ct) => Task.FromResult(false);
}

/// <summary>Configuração do vínculo com contas existentes.</summary>
public sealed class VinculoBtsOptions
{
    /// <summary>Página de login do <b>seu</b> sistema (senha, Google…). Obrigatória.</summary>
    public string CaminhoLoginProprio { get; set; } = "";

    /// <summary>Nome do parâmetro de retorno da sua página de login (ASP.NET usa <c>ReturnUrl</c>).</summary>
    public string ParametroRetorno { get; set; } = "ReturnUrl";

    /// <summary>Rotas do vínculo (o pacote cria as páginas).</summary>
    public string Caminho { get; set; } = "/vincular/bts";

    /// <summary>Por quanto tempo a pessoa pode concluir o vínculo depois de entrar com a BTS.</summary>
    public TimeSpan Validade { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Liga direto quando o e-mail bate, sem pedir o login antigo. Use <b>só</b> se o seu sistema também confirmou
    /// o e-mail das contas (link de confirmação ou Google verificado): aí os dois lados provaram o mesmo e-mail.
    /// Risco: e-mail trocado ou reaproveitado pelo provedor. Padrão: desligado.
    /// </summary>
    public bool VinculoAutomatico { get; set; }

    /// <summary>Nome do site nas páginas do vínculo (ex.: "Deluxe").</summary>
    public string NomeSite { get; set; } = "este site";

    internal void Validar()
    {
        if (string.IsNullOrWhiteSpace(CaminhoLoginProprio) || !CaminhoLoginProprio.StartsWith('/'))
            throw new InvalidOperationException("Bts: informe CaminhoLoginProprio (a sua página de login, começando com '/').");
        if (!Caminho.StartsWith('/') || Caminho.EndsWith('/'))
            throw new InvalidOperationException("Bts: o Caminho do vínculo precisa começar com '/' e não terminar com '/'.");
        if (Validade <= TimeSpan.Zero || Validade > TimeSpan.FromHours(1))
            throw new InvalidOperationException("Bts: a Validade do vínculo precisa ficar entre 1 segundo e 1 hora.");
    }
}
