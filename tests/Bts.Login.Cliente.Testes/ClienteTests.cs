namespace Bts.Login.Cliente.Testes;

public class ClienteTests
{
    private static (BtsCliente Cliente, BtsFalsa Bts) Criar(Action<BtsClienteOptions>? configurar = null)
    {
        var bts = new BtsFalsa();
        var o = new BtsClienteOptions
        {
            Emissor = BtsFalsa.Emissor,
            ClientId = BtsFalsa.ClientId,
            RetornoUri = "app.teste:/bts"
        };
        o.Escopos.Add("phone");
        o.Escopos.Add("bts.niveis");
        o.Escopos.Add("offline_access");
        configurar?.Invoke(o);
        return (new BtsCliente(o, bts, new HttpClient(bts)), bts);
    }

    [Fact]
    public async Task Login_completo_devolve_a_pessoa_e_os_tokens()
    {
        var (cliente, bts) = Criar();
        var s = await cliente.EntrarAsync();

        Assert.Equal("sub-do-app", s.Pessoa.Id);
        Assert.Equal("Maria Teste", s.Pessoa.Nome);
        Assert.Equal("maria@teste.com", s.Pessoa.Email);
        Assert.True(s.Pessoa.EmailConfirmado);
        Assert.Equal("+5511999990000", s.Pessoa.Celular);
        Assert.Equal([1, 3], s.Pessoa.Niveis);
        Assert.True(s.Pessoa.TemNivel(3));
        Assert.StartsWith("at-", s.AccessToken);
        Assert.StartsWith("rt-", s.RefreshToken);
        Assert.True(s.AccessTokenExpiraEm > DateTimeOffset.UtcNow.AddMinutes(14));

        var q = BtsFalsa.Consulta(bts.UltimoAutorizar!.Query);
        Assert.Equal("https://bts.teste/connect/authorize", bts.UltimoAutorizar.GetLeftPart(UriPartial.Path));
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.Equal("code", q["response_type"]);
        Assert.Equal("app.teste:/bts", q["redirect_uri"]);
        Assert.Equal("openid profile email phone bts.niveis offline_access", q["scope"]);
        Assert.False(q.ContainsKey("prompt"));
        Assert.False(bts.UltimoToken.ContainsKey("client_secret"));
    }

    [Fact]
    public async Task Forcar_senha_manda_prompt_login()
    {
        var (cliente, bts) = Criar();
        await cliente.EntrarAsync(forcarSenha: true);
        Assert.Equal("login", BtsFalsa.Consulta(bts.UltimoAutorizar!.Query)["prompt"]);
    }

    [Fact]
    public async Task Cancelar_no_navegador_vira_BtsCancelado()
    {
        var (cliente, bts) = Criar();
        bts.Cancelar = true;
        await Assert.ThrowsAsync<BtsCanceladoException>(() => cliente.EntrarAsync());
    }

    [Fact]
    public async Task Tocar_em_cancelar_na_bts_vira_BtsCancelado()
    {
        var (cliente, bts) = Criar();
        bts.Volta = (a, r) => new Uri($"{r}?error=access_denied&state={Uri.EscapeDataString(BtsFalsa.Consulta(a.Query)["state"])}");
        await Assert.ThrowsAsync<BtsCanceladoException>(() => cliente.EntrarAsync());
    }

    public static TheoryData<string> VoltasInvalidas => new()
    {
        "?code=x&state=outro",                         // state de outro login (CSRF)
        "?code=x",                                     // sem state
        "?code=x&state={s}&state={s}",                 // parâmetro repetido
        "?code=x&state={s}&iss=https%3A%2F%2Fmal.exemplo%2F", // outro emissor (mix-up)
        "?state={s}",                                  // sem código
        "?error=server_error&state={s}"
    };

    [Theory]
    [MemberData(nameof(VoltasInvalidas))]
    public async Task Volta_invalida_e_recusada(string consulta)
    {
        var (cliente, bts) = Criar();
        bts.Volta = (a, r) => new Uri(r + consulta.Replace("{s}", Uri.EscapeDataString(BtsFalsa.Consulta(a.Query)["state"])));
        var e = await Assert.ThrowsAsync<BtsException>(() => cliente.EntrarAsync());
        Assert.IsNotType<BtsCanceladoException>(e);
    }

    [Fact]
    public async Task Codigo_trocado_sem_o_verificador_certo_e_recusado()
    {
        // Um código "roubado" de outro login não serve: o PKCE (S256) não bate
        var (cliente, bts) = Criar();
        string? codigoAlheio = null;
        bts.Volta = (a, r) =>
        {
            var q = BtsFalsa.Consulta(a.Query);
            var falso = new Uri(a.GetLeftPart(UriPartial.Path) + "?" + string.Join('&', q.Select(p =>
                $"{p.Key}={Uri.EscapeDataString(p.Key == "code_challenge" ? "desafio-de-outro" : p.Value)}")));
            var volta = bts.AbrirSemVolta(falso, r);
            codigoAlheio = BtsFalsa.Consulta(volta.Query)["code"];
            return volta;
        };
        var e = await Assert.ThrowsAsync<BtsException>(() => cliente.EntrarAsync());
        Assert.Equal("invalid_grant", e.Erro);
        Assert.NotNull(codigoAlheio);
    }

    [Theory]
    [InlineData("chave")]
    [InlineData("audiencia")]
    [InlineData("nonce")]
    [InlineData("vencido")]
    public async Task Id_token_invalido_e_recusado(string defeito)
    {
        var (cliente, bts) = Criar();
        switch (defeito)
        {
            case "chave": bts.ChaveAssinatura = bts.ChaveEstranha; break;
            case "audiencia": bts.Audiencia = "outro-app"; break;
            case "nonce": bts.NonceForcado = "nonce-de-outro-login"; break;
            case "vencido": bts.Expira = DateTime.UtcNow.AddMinutes(-10); break;
        }
        await Assert.ThrowsAsync<BtsException>(() => cliente.EntrarAsync());
    }

    [Fact]
    public async Task Renovar_devolve_tokens_novos_e_sessao_encerrada_pede_login()
    {
        var (cliente, bts) = Criar();
        var s = await cliente.EntrarAsync();
        var nova = await cliente.RenovarAsync(s.RefreshToken!);
        Assert.NotEqual(s.AccessToken, nova.AccessToken);
        Assert.NotEqual(s.RefreshToken, nova.RefreshToken);
        Assert.Equal("sub-do-app", nova.Pessoa.Id);
        Assert.Equal("refresh_token", bts.UltimoToken["grant_type"]);

        bts.RefreshValido = false;
        var e = await Assert.ThrowsAsync<BtsException>(() => cliente.RenovarAsync(nova.RefreshToken!));
        Assert.Equal("invalid_grant", e.Erro);
    }

    [Fact]
    public async Task Sair_revoga_o_refresh_token()
    {
        var (cliente, bts) = Criar();
        var s = await cliente.EntrarAsync();
        await cliente.SairAsync(s);
        Assert.Equal([s.RefreshToken!], bts.Revogados);
    }

    [Theory]
    [InlineData("", "app:/x")]
    [InlineData("app", "")]
    public void Configuracao_incompleta_e_recusada(string clientId, string retorno) =>
        Assert.Throws<InvalidOperationException>(() =>
            new BtsCliente(new BtsClienteOptions { ClientId = clientId, RetornoUri = retorno }, new BtsFalsa()));

    [Fact]
    public void Emissor_sem_https_e_recusado() =>
        Assert.Throws<InvalidOperationException>(() => new BtsCliente(
            new BtsClienteOptions { Emissor = "http://bts.exemplo/", ClientId = "a", RetornoUri = "app:/x" }, new BtsFalsa()));
}

public class RetornoLocalTests
{
    [Fact]
    public async Task Login_pelo_navegador_com_retorno_em_127_0_0_1()
    {
        var bts = new BtsFalsa();
        using var http = new HttpClient(); // o "navegador" de verdade, chamando o retorno local
        string? pagina = null;
        using var navegador = new NavegadorRetornoLocal(async autorizar =>
        {
            // O "navegador": a BTS (falsa) devolve o endereço de volta e o navegador vai até ele
            var q = BtsFalsa.Consulta(autorizar.Query);
            var volta = bts.AbrirSemVolta(autorizar, new Uri(q["redirect_uri"]));
            _ = Task.Run(async () =>
            {
                await http.GetAsync(new Uri(new Uri(q["redirect_uri"]), "/favicon.ico")); // barulho que deve ser ignorado
                pagina = await http.GetStringAsync(volta);
            });
        });
        var o = new BtsClienteOptions { Emissor = BtsFalsa.Emissor, ClientId = BtsFalsa.ClientId, RetornoUri = "http://127.0.0.1/bts" };
        var cliente = new BtsCliente(o, navegador, new HttpClient(bts));

        var s = await cliente.EntrarAsync();

        Assert.Equal("sub-do-app", s.Pessoa.Id);
        var redirect = new Uri(BtsFalsa.Consulta(bts.UltimoAutorizar!.Query)["redirect_uri"]);
        Assert.Equal("127.0.0.1", redirect.Host);
        Assert.NotEqual(80, redirect.Port); // porta escolhida na hora
        Assert.Equal("/bts", redirect.AbsolutePath);
        for (var i = 0; i < 50 && pagina is null; i++) await Task.Delay(20);
        Assert.Contains("Pode fechar esta aba", pagina);

        // Depois do login a porta é fechada
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => http.GetAsync(redirect));
    }

    [Fact]
    public async Task Retorno_local_exige_127_0_0_1()
    {
        using var navegador = new NavegadorRetornoLocal(_ => Task.CompletedTask);
        await Assert.ThrowsAsync<BtsException>(() => navegador.PrepararRetornoAsync(new Uri("http://localhost/bts"), default));
        await Assert.ThrowsAsync<BtsException>(() => navegador.PrepararRetornoAsync(new Uri("app:/bts"), default));
    }

    [Fact]
    public async Task Ninguem_volta_do_navegador_vira_cancelado()
    {
        var bts = new BtsFalsa();
        using var navegador = new NavegadorRetornoLocal(_ => Task.CompletedTask);
        var o = new BtsClienteOptions
        {
            Emissor = BtsFalsa.Emissor, ClientId = BtsFalsa.ClientId, RetornoUri = "http://127.0.0.1/bts",
            EsperaMaxima = TimeSpan.FromMilliseconds(300)
        };
        await Assert.ThrowsAsync<BtsCanceladoException>(() => new BtsCliente(o, navegador, new HttpClient(bts)).EntrarAsync());
    }
}
