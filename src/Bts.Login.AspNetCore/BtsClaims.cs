using System.Globalization;
using System.Security.Claims;
using System.Text.Json;

namespace Bts.Login.AspNetCore;

/// <summary>Claims que a BTS entrega (só as dos escopos que a pessoa permitiu).</summary>
public static class BtsClaims
{
    /// <summary>Identificador da pessoa <b>para o seu site</b> (cada parceiro recebe um diferente). Use como chave da conta.</summary>
    public const string Id = "sub";
    public const string Nome = "name";
    public const string Email = "email";
    public const string EmailConfirmado = "email_verified";
    public const string Celular = "phone_number";
    public const string CelularConfirmado = "phone_number_verified";
    /// <summary>Níveis de verificação: 1 = e-mail, 2 = CPF, 3 = celular, 4 = documento/biometria.</summary>
    public const string Niveis = "bts_niveis";
    /// <summary>Identificador da conta no <b>seu</b> sistema, quando o vínculo (<c>AddVinculoBts</c>) está ligado.</summary>
    public const string Conta = "bts_conta";
    /// <summary>Quando a pessoa entrou na BTS (segundos Unix). Renovar o token não muda este valor.</summary>
    public const string AutenticadoEm = "auth_time";
    /// <summary>Como a pessoa entrou na BTS (lista; valores em <see cref="BtsFormasDeEntrar"/>).</summary>
    public const string FormasDeEntrar = "amr";
}

/// <summary>Valores do claim <c>amr</c> (como a pessoa entrou na BTS).</summary>
public static class BtsFormasDeEntrar
{
    /// <summary>Digitou a senha da BTS.</summary>
    public const string Senha = "pwd";
    /// <summary>Digitou o código do app autenticador (ou de recuperação).</summary>
    public const string CodigoAutenticador = "otp";
    /// <summary>Usou mais de um fator (senha + código).</summary>
    public const string DuasEtapas = "mfa";
    /// <summary>Entrou pelo Google (sem a senha da BTS). O Google não aceita pedido para digitar a senha de novo.</summary>
    public const string Google = "google";
}

/// <summary>Atalhos para ler a pessoa que entrou com a BTS.</summary>
public static class BtsUsuarioExtensions
{
    public static string? IdBts(this ClaimsPrincipal u) => u.FindFirst(BtsClaims.Id)?.Value;

    /// <summary>Conta no seu sistema ligada a esta pessoa (com <c>AddVinculoBts</c>).</summary>
    public static string? ContaParceiro(this ClaimsPrincipal u) => u.FindFirst(BtsClaims.Conta)?.Value;
    public static string? NomeBts(this ClaimsPrincipal u) => u.FindFirst(BtsClaims.Nome)?.Value;
    public static string? EmailBts(this ClaimsPrincipal u) => u.FindFirst(BtsClaims.Email)?.Value;

    /// <summary>Celular em formato internacional (+55...), só se confirmado e se o escopo <c>phone</c> foi permitido.</summary>
    public static string? CelularBts(this ClaimsPrincipal u) => u.FindFirst(BtsClaims.Celular)?.Value;

    /// <summary>
    /// Níveis confirmados no momento do login (escopo <c>bts.niveis</c>). Para ver um nível novo,
    /// a pessoa precisa entrar de novo.
    /// </summary>
    public static IReadOnlySet<int> NiveisBts(this ClaimsPrincipal u)
    {
        var niveis = new SortedSet<int>();
        foreach (var c in u.FindAll(BtsClaims.Niveis))
        {
            var v = c.Value.Trim();
            if (v.StartsWith('['))
            {
                try
                {
                    foreach (var e in JsonDocument.Parse(v).RootElement.EnumerateArray())
                        if (e.TryGetInt32(out var n)) niveis.Add(n);
                }
                catch (JsonException) { }
            }
            else if (int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n))
                niveis.Add(n);
        }
        return niveis;
    }

    public static bool TemNivelBts(this ClaimsPrincipal u, int nivel) => u.NiveisBts().Contains(nivel);

    /// <summary>Quando a pessoa entrou na BTS (claim <c>auth_time</c>). null = a BTS não informou.</summary>
    public static DateTimeOffset? AutenticadoEmBts(this ClaimsPrincipal u) =>
        long.TryParse(u.FindFirst(BtsClaims.AutenticadoEm)?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var s)
            ? DateTimeOffset.FromUnixTimeSeconds(s)
            : null;

    /// <summary>Como a pessoa entrou na BTS (claim <c>amr</c>): <see cref="BtsFormasDeEntrar"/>.</summary>
    public static IReadOnlyList<string> FormasDeEntrarBts(this ClaimsPrincipal u)
    {
        var formas = new List<string>();
        foreach (var c in u.FindAll(BtsClaims.FormasDeEntrar))
        {
            var v = c.Value.Trim();
            if (v.StartsWith('['))
            {
                try
                {
                    foreach (var e in JsonDocument.Parse(v).RootElement.EnumerateArray())
                        if (e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 } f) formas.Add(f);
                }
                catch (JsonException) { }
            }
            else if (v.Length > 0) formas.Add(v);
        }
        return formas.Distinct().ToList();
    }

    /// <summary>Entrou digitando a senha da BTS (não só pelo Google).</summary>
    public static bool EntrouComSenhaBts(this ClaimsPrincipal u) => u.FormasDeEntrarBts().Contains(BtsFormasDeEntrar.Senha);

    /// <summary>
    /// A pessoa entrou na BTS há no máximo <paramref name="limite"/> (e com a senha, se <paramref name="exigirSenha"/>).
    /// Sem <c>auth_time</c> no token: não é recente.
    /// </summary>
    public static bool LoginRecenteBts(this ClaimsPrincipal u, TimeSpan limite, bool exigirSenha = false,
        TimeProvider? relogio = null)
    {
        if (u.AutenticadoEmBts() is not { } em) return false;
        var agora = (relogio ?? TimeProvider.System).GetUtcNow();
        if (agora - em > limite + BtsPadroes.FolgaRelogio) return false;
        return !exigirSenha || u.EntrouComSenhaBts();
    }
}
