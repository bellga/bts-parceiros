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
}

/// <summary>Atalhos para ler a pessoa que entrou com a BTS.</summary>
public static class BtsUsuarioExtensions
{
    public static string? IdBts(this ClaimsPrincipal u) => u.FindFirst(BtsClaims.Id)?.Value;
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
}
