namespace Bts.Login.AspNetCore;

/// <summary>Nomes e endereços fixos do "Entrar com BTS".</summary>
public static class BtsPadroes
{
    /// <summary>Emissor (issuer) da BTS em produção.</summary>
    public const string Emissor = "https://login.bellga.tech/";

    /// <summary>Esquema de autenticação do login na BTS (OpenID Connect).</summary>
    public const string Esquema = "Bts";

    /// <summary>Esquema do cookie de sessão do site do parceiro.</summary>
    public const string EsquemaCookie = "Bts.Cookie";

    /// <summary>Esquema da validação dos tokens da BTS na API do parceiro.</summary>
    public const string EsquemaBearer = "Bts.Bearer";

    public const string NomeExibicao = "BTS";
}

/// <summary>Escopos que o parceiro pode pedir. Cada um precisa estar liberado no cadastro do parceiro.</summary>
public static class BtsEscopos
{
    public const string OpenId = "openid";
    /// <summary>Nome da pessoa (claim <c>name</c>).</summary>
    public const string Perfil = "profile";
    /// <summary>E-mail confirmado (<c>email</c>, <c>email_verified</c>).</summary>
    public const string Email = "email";
    /// <summary>Celular, se confirmado (<c>phone_number</c>, <c>phone_number_verified</c>).</summary>
    public const string Celular = "phone";
    /// <summary>Níveis de verificação da conta (<c>bts_niveis</c>).</summary>
    public const string Niveis = "bts.niveis";
    /// <summary>Refresh token (para apps que continuam conectados).</summary>
    public const string Offline = "offline_access";
}

/// <summary>Configuração do login com a BTS no site do parceiro.</summary>
public sealed class BtsLoginOptions
{
    /// <summary>Endereço da BTS. Só mude para testes.</summary>
    public string Emissor { get; set; } = BtsPadroes.Emissor;

    /// <summary>Identificador do parceiro, recebido no cadastro.</summary>
    public string ClientId { get; set; } = "";

    /// <summary>
    /// Segredo do parceiro (sites com servidor). Guarde fora do código (variável de ambiente ou cofre).
    /// Vazio = cliente público (só PKCE).
    /// </summary>
    public string? Segredo { get; set; }

    /// <summary>Escopos pedidos. <c>openid</c> é sempre incluído.</summary>
    public ISet<string> Escopos { get; } = new HashSet<string> { BtsEscopos.OpenId, BtsEscopos.Perfil, BtsEscopos.Email };

    /// <summary>Rota do site que inicia o login (destino do botão). Aceita <c>?retorno=/caminho-local</c>.</summary>
    public string CaminhoEntrar { get; set; } = "/entrar/bts";

    /// <summary>Rota (POST, com antifalsificação) que encerra a sessão no site e na BTS.</summary>
    public string CaminhoSair { get; set; } = "/sair/bts";

    /// <summary>Retorno do login. Cadastre <c>https://seu-site/signin-bts</c> como RedirectUri na BTS.</summary>
    public string CaminhoRetorno { get; set; } = "/signin-bts";

    /// <summary>Retorno da saída. Cadastre <c>https://seu-site/signout-callback-bts</c> como PostLogoutRedirectUri.</summary>
    public string CaminhoRetornoSaida { get; set; } = "/signout-callback-bts";

    /// <summary>Guarda os tokens no cookie (só se o site precisar do access token). Padrão: não.</summary>
    public bool GuardarTokens { get; set; }

    internal void Validar()
    {
        if (string.IsNullOrWhiteSpace(ClientId))
            throw new InvalidOperationException("Bts: informe o ClientId recebido no cadastro do parceiro.");
        if (!Uri.TryCreate(Emissor, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && !uri.IsLoopback))
            throw new InvalidOperationException("Bts: o Emissor precisa ser um endereço https.");
        foreach (var c in new[] { CaminhoEntrar, CaminhoSair, CaminhoRetorno, CaminhoRetornoSaida })
            if (!c.StartsWith('/'))
                throw new InvalidOperationException($"Bts: o caminho '{c}' precisa começar com '/'.");
    }
}

/// <summary>Configuração da validação dos tokens da BTS na API do parceiro.</summary>
public sealed class BtsBearerOptions
{
    public string Emissor { get; set; } = BtsPadroes.Emissor;

    /// <summary>ClientIds dos apps do parceiro cujos tokens a API aceita (o <c>aud</c> do token é o ClientId).</summary>
    public ISet<string> ClientIds { get; } = new HashSet<string>();
}
