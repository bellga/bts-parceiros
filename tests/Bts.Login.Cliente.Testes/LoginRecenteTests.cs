using System.Net;
using System.Net.Http.Headers;

namespace Bts.Login.Cliente.Testes;

/// <summary>Ação sensível no app: prompt=login, max_age, conferência do auth_time e o 401 da API do parceiro.</summary>
public class LoginRecenteTests
{
    private static (BtsCliente Cliente, BtsFalsa Bts) Criar()
    {
        var bts = new BtsFalsa();
        var o = new BtsClienteOptions { Emissor = BtsFalsa.Emissor, ClientId = BtsFalsa.ClientId, RetornoUri = "app.teste:/bts" };
        o.Escopos.Add("offline_access");
        return (new BtsCliente(o, bts, new HttpClient(bts)), bts);
    }

    [Fact]
    public async Task Pessoa_traz_quando_e_como_entrou()
    {
        var (cliente, bts) = Criar();
        var quando = DateTimeOffset.UtcNow.AddMinutes(-3);
        bts.AutenticadoEm = quando;
        bts.Formas = ["pwd", "otp", "mfa"];
        var s = await cliente.EntrarAsync();
        Assert.Equal(quando.ToUnixTimeSeconds(), s.Pessoa.AutenticadoEm!.Value.ToUnixTimeSeconds());
        Assert.Equal(["pwd", "otp", "mfa"], s.Pessoa.FormasDeEntrar);
        Assert.True(s.Pessoa.EntrouComSenha);

        bts.Formas = ["google"];
        var renovada = await cliente.RenovarAsync(s.RefreshToken!);
        Assert.Equal(["google"], renovada.Pessoa.FormasDeEntrar);
        Assert.False(renovada.Pessoa.EntrouComSenha);
    }

    [Fact]
    public async Task Login_comum_aceita_login_antigo_e_sem_auth_time()
    {
        var (cliente, bts) = Criar();
        bts.AutenticadoEm = DateTimeOffset.UtcNow.AddDays(-30);
        await cliente.EntrarAsync();
        bts.EmitirAutenticadoEm = false;
        Assert.Null((await cliente.EntrarAsync()).Pessoa.AutenticadoEm);
    }

    [Fact]
    public async Task Pedir_senha_manda_prompt_login_e_confere_que_o_login_e_deste_pedido()
    {
        var (cliente, bts) = Criar();
        var s = await cliente.EntrarAsync(new BtsOpcoesEntrar { PedirSenha = true });
        Assert.Equal("login", BtsFalsa.Consulta(bts.UltimoAutorizar!.Query)["prompt"]);
        Assert.NotNull(s.Pessoa.AutenticadoEm);

        // A volta trouxe um login antigo (o navegador pulou a senha): não vale
        bts.AutenticadoEm = DateTimeOffset.UtcNow.AddMinutes(-10);
        var e = await Assert.ThrowsAsync<BtsException>(() => cliente.EntrarAsync(new BtsOpcoesEntrar { PedirSenha = true }));
        Assert.Equal(BtsCliente.ErroLoginRecente, e.Erro);

        bts.AutenticadoEm = null;
        bts.EmitirAutenticadoEm = false;
        await Assert.ThrowsAsync<BtsException>(() => cliente.EntrarAsync(forcarSenha: true));
    }

    [Fact]
    public async Task Login_recente_manda_max_age_e_confere_o_prazo()
    {
        var (cliente, bts) = Criar();
        bts.AutenticadoEm = DateTimeOffset.UtcNow.AddMinutes(-3);
        await cliente.EntrarAsync(new BtsOpcoesEntrar { LoginRecente = TimeSpan.FromMinutes(5) });
        var q = BtsFalsa.Consulta(bts.UltimoAutorizar!.Query);
        Assert.Equal("300", q["max_age"]);
        Assert.False(q.ContainsKey("prompt"));

        bts.AutenticadoEm = DateTimeOffset.UtcNow.AddMinutes(-10);
        var e = await Assert.ThrowsAsync<BtsException>(() =>
            cliente.EntrarAsync(new BtsOpcoesEntrar { LoginRecente = TimeSpan.FromMinutes(5) }));
        Assert.Equal(BtsCliente.ErroLoginRecente, e.Erro);
    }

    [Theory]
    [InlineData("Bearer error=\"insufficient_user_authentication\", error_description=\"Entre de novo, por favor.\", max_age=300", true, 300)]
    [InlineData("Bearer max_age=60,error=\"insufficient_user_authentication\"", true, 60)]
    [InlineData("Bearer error=\"insufficient_user_authentication\"", true, null)]
    [InlineData("Bearer error=\"invalid_token\"", false, null)]
    [InlineData("Bearer", false, null)]
    public void Le_o_401_da_api_que_pede_login_recente(string cabecalho, bool pede, int? segundos)
    {
        var r = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        r.Headers.WwwAuthenticate.Add(AuthenticationHeaderValue.Parse(cabecalho));
        Assert.Equal(pede, BtsCliente.PedeLoginRecente(r, out var limite));
        Assert.Equal(segundos is null ? null : TimeSpan.FromSeconds(segundos.Value), limite);
    }

    [Fact]
    public void Outros_status_nao_pedem_login_recente()
    {
        var r = new HttpResponseMessage(HttpStatusCode.Forbidden);
        r.Headers.WwwAuthenticate.Add(AuthenticationHeaderValue.Parse("Bearer error=\"insufficient_user_authentication\""));
        Assert.False(BtsCliente.PedeLoginRecente(r, out _));
    }
}
