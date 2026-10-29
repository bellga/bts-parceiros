# Entrar com BTS — pacotes para parceiros

Pacotes .NET para sites e apps que querem o login da **Bellga Tech Solutions (BTS)**: a pessoa entra com a conta BTS,
escolhe o que compartilhar e o seu sistema recebe os dados já confirmados (e-mail, celular, níveis de verificação).

| Pacote | Para quê |
|---|---|
| `Bts.Login.AspNetCore` | Site ASP.NET Core (login + sessão), API (validar os tokens dos seus apps) e o botão oficial |
| `Bts.Login.Cliente` | App .NET de qualquer tipo (o núcleo do login: PKCE, troca do código, validação, renovação, saída) + retorno local para apps de computador |
| `Bts.Login.Maui` | App .NET MAUI: navegador do sistema (Android/iOS/Windows) e o controle `BotaoBts` |

Por baixo é OpenID Connect padrão (Authorization Code + PKCE S256), emissor `https://login.bellga.tech/`.
Botão e regras de uso da marca: https://bellga.tech/marca.html

## 1. Cadastro do parceiro

Peça o cadastro à BTS informando:

- **Nome** que aparece na tela de autorização ("Fulano quer: …").
- **Endereços de volta** (precisam ser exatos):
  - site: `https://SEU-SITE/signin-bts` e, para a saída, `https://SEU-SITE/signout-callback-bts`;
  - app de celular: um esquema próprio com o domínio invertido, por exemplo `com.exemplo.app:/bts`;
  - app de computador: `http://127.0.0.1/bts` (sem porta — o app escolhe uma porta livre na hora).
- **Escopos** que vai pedir (só o necessário):

| Escopo | O que chega |
|---|---|
| `openid` | `sub`: identificador da pessoa **só para você** (cada parceiro recebe um diferente). Use como chave da conta. |
| `profile` | `name` |
| `email` | `email`, `email_verified` (sempre confirmado) |
| `phone` | `phone_number` (+55…), `phone_number_verified` — só se a pessoa confirmou o celular |
| `bts.niveis` | `bts_niveis`: 1 = e-mail, 2 = CPF, 3 = celular, 4 = documento/biometria |
| `offline_access` | refresh token (apps que continuam conectados) |

Você recebe o **ClientId** e, para site com servidor, um **segredo** (guarde fora do código).
Apps (celular/computador) não têm segredo: a segurança vem do PKCE.

## 2. Instalação

Os pacotes estão no [nuget.org](https://www.nuget.org/packages?q=Bts.Login) (sem token, sem configuração):

```bash
dotnet add package Bts.Login.AspNetCore   # site e API
dotnet add package Bts.Login.Maui         # app MAUI (traz o Bts.Login.Cliente junto)
dotnet add package Bts.Login.Cliente      # outros apps .NET
```

Os pacotes saem só pelo workflow deste repositório (Trusted Publishing, sem chave guardada) e trazem
símbolos com Source Link. Se o seu `nuget.config` usa `packageSourceMapping`, mapeie `Bts.Login.*` para o nuget.org.

## 3. Site ASP.NET Core

```csharp
builder.Services.AddEntrarComBts(o =>
{
    o.ClientId = builder.Configuration["Bts:ClientId"]!;
    o.Segredo = builder.Configuration["Bts:Segredo"];   // user-secrets / variável de ambiente
    o.Escopos.Add(BtsEscopos.Celular);
    o.Escopos.Add(BtsEscopos.Niveis);
});
builder.Services.AddAuthorization(o => o.AddPolicy("celular", p => p.ExigirNivelBts(3)));

var app = builder.Build();
app.MapStaticAssets();     // CSS do botão
app.UseAuthentication();
app.UseAuthorization();
app.MapEntrarComBts();     // GET /entrar/bts?retorno=/caminho  e  POST /sair/bts (com antifalsificação)
```

Na página (Razor, com `@addTagHelper *, Bts.Login.AspNetCore`):

```html
<link rel="stylesheet" href="/_content/Bts.Login.AspNetCore/botao-bts.css">
<bts-botao />
<bts-botao tema="Claro" texto="Continuar" retorno="/carrinho" />
<bts-botao so-icone="true" />
```

Sem Razor: `BtsBotao.Html("/entrar/bts")`. O botão é um link comum, sem script: funciona com qualquer CSP.

Lendo a pessoa: `User.IdBts()`, `User.NomeBts()`, `User.EmailBts()`, `User.CelularBts()`, `User.NiveisBts()`,
`User.TemNivelBts(3)`. Os níveis são os do momento do login: para ver um nível novo, a pessoa entra de novo.

Já usa outro login (Google, senha própria)? Em vez de `AddEntrarComBts`, adicione ao seu `AddAuthentication`:
`.AddBts(o => …, esquemaSessao: "SeuCookie")`.

Exemplo completo: `exemplos/SiteParceiro`.

## 4. Já tenho usuários: vincular contas existentes

Seu sistema já tem contas (senha própria, Google, Facebook…) e muitas pessoas também têm conta BTS com o mesmo
e-mail? O pacote liga as duas **sem nunca juntar contas só porque o e-mail é igual** (isso abriria caminho para
roubo de conta). Você implementa só o acesso às suas contas:

```csharp
public class MeuVinculo(MeuDbContext db) : IVinculoBts
{
    public Task<string?> ContaPorSubAsync(string sub, CancellationToken ct) => ...;     // conta já ligada?
    public Task<string?> ContaPorEmailAsync(string email, CancellationToken ct) => ...; // conta com o mesmo e-mail?
    public Task VincularAsync(string conta, BtsPessoa pessoa, CancellationToken ct) => ...; // grava o sub na conta
    public Task<string> CriarContaAsync(BtsPessoa pessoa, CancellationToken ct) => ...;     // conta nova, já ligada
    public Task<string?> ContaAtualAsync(HttpContext ctx, CancellationToken ct) => ...;   // quem está conectado no SEU login
}

builder.Services.AddEntrarComBts(o => { /* ... */ })
    .AddVinculoBts<MeuVinculo>(o =>
    {
        o.CaminhoLoginProprio = "/login";   // sua página de login (recebe ?ReturnUrl=)
        o.NomeSite = "Meu Site";
    });
```

O que acontece quando a pessoa entra com a BTS:

1. **`sub` já ligado** a uma conta sua → entra nela.
2. **E-mail igual** ao de uma conta sua → página “Você já tem uma conta aqui”: a pessoa entra **uma vez** do jeito
   de sempre, confirma (“Ligar e continuar”) e só então o `sub` é gravado. A identidade da BTS fica guardada por
   10 minutos num cookie cifrado; “Agora não” desiste sem ligar nada. Se ela entrar numa conta diferente, nada é ligado.
3. **Nenhuma conta** → `CriarContaAsync`.

Depois disso, `User.ContaParceiro()` traz o identificador da conta no seu sistema. Quem já está conectado no seu login
também pode ligar a conta BTS por um botão “Vincular conta BTS” com `href="/vincular/bts/iniciar"` (serve até quando os
e-mails são diferentes). Uma conta BTS já ligada a outra conta sua não é tomada.

- `o.VinculoAutomatico = true` liga direto pelo e-mail, sem pedir o login antigo. Use **só** se o seu sistema também
  confirmou o e-mail das contas (link de confirmação ou Google verificado). Risco: e-mail trocado ou reaproveitado pelo provedor.
- Usa ASP.NET Identity ou outro esquema? Implemente também `EntrarAsync` (opcional) para conectar a pessoa do seu jeito.
- O cookie do seu login precisa ser `SameSite=Lax` (o padrão do ASP.NET) para o “Vincular conta BTS” funcionar.
- As páginas do vínculo são HTML simples, sem script e sem estilo inline (funcionam com qualquer CSP).
- App com API própria (sem site): faça a mesma lógica na API, ao receber o primeiro token de cada `sub`: nunca ligue
  pelo e-mail sem a pessoa provar que é dona da conta antiga (entrando nela pelo app).

## 5. API do parceiro (tokens dos seus apps)

```csharp
builder.Services.AddAuthentication(BtsPadroes.EsquemaBearer)
    .AddBtsBearer(o => o.ClientIds.Add("meu-app"));
```

Só aceita **access token** da BTS (`typ` = `at+jwt`) emitido para os seus ClientIds; id_token não serve de chave.

O access token já traz os dados da pessoa — a API pode confiar só nele, sem chamar o `/connect/userinfo` a cada pedido:

| Claim | Quando vem |
|---|---|
| `sub` | sempre (identificador da pessoa só para você; use como chave) |
| `name` | escopo `profile` |
| `email`, `email_verified` | escopo `email` (sempre confirmado) |
| `phone_number`, `phone_number_verified` | escopo `phone` **e** celular confirmado |
| `bts_niveis` | escopo `bts.niveis` (lista: `[1, 3]`) |

Na API: `User.IdBts()`, `User.EmailBts()`, `User.CelularBts()`, `User.NiveisBts()`, `User.TemNivelBts(3)` e a política
`ExigirNivelBts(3)` funcionam igual ao site.

- O token vale **15 minutos** e mostra os dados de quando foi emitido. A cada renovação (refresh token) a BTS relê a
  conta: um nível novo ou um celular que deixou de valer aparece no próximo token. Para uma ação crítica que precisa do
  dado deste instante, chame `https://login.bellga.tech/connect/userinfo` com o mesmo token (ele lê a conta na hora).
- Claim ausente = **não permitido ou não confirmado**, nunca “vazio”. Sem `phone_number`, a pessoa não tem celular
  confirmado ou não liberou o escopo `phone`.

## 6. App .NET MAUI

```csharp
var bts = BtsLoginMaui.Criar(
    clientId: "meu-app",
    retornoCelular: "com.exemplo.app:/bts",
    retornoComputador: "http://127.0.0.1/bts",
    configurar: o => { o.Escopos.Add("phone"); o.Escopos.Add("bts.niveis"); o.Escopos.Add("offline_access"); });

try
{
    var sessao = await bts.EntrarAsync();
    // sessao.Pessoa (Id, Nome, Email, Celular, Niveis), sessao.AccessToken, sessao.RefreshToken
    await SecureStorage.Default.SetAsync("bts_refresh", sessao.RefreshToken!);
}
catch (BtsCanceladoException) { /* a pessoa desistiu */ }
```

- Renovar: `await bts.RenovarAsync(refresh)` — o refresh token muda a cada uso; guarde o novo. `BtsException` com
  `Erro == "invalid_grant"` = sessão encerrada (senha trocada, conta excluída…): peça o login de novo.
- Sair: `await bts.SairAsync(sessao)` (revoga o refresh token) e apague o que guardou.
- Botão: `new BotaoBts { Tema = TemaBotaoBts.Escuro, Texto = TextoBotaoBts.Entrar }` com `Clicked` ou `Command`.
- Guarde tokens só no `SecureStorage`, nunca em `Preferences` ou arquivo. Não registre tokens em log.

**Android** — a volta chega por uma Activity do seu app (troque o esquema):

```csharp
// Platforms/Android/BtsRetornoActivity.cs
[Activity(NoHistory = true, LaunchMode = LaunchMode.SingleTop, Exported = true)]
[IntentFilter([Intent.ActionView], Categories = [Intent.CategoryDefault, Intent.CategoryBrowsable],
    DataScheme = "com.exemplo.app")]
public class BtsRetornoActivity : WebAuthenticatorCallbackActivity { }
```

E no `AndroidManifest.xml`, dentro de `<manifest>`:

```xml
<queries>
  <intent><action android:name="android.support.customtabs.action.CustomTabsService" /></intent>
</queries>
```

**iOS** — registre o esquema em `Info.plist` (`CFBundleURLTypes` → `CFBundleURLSchemes` = `com.exemplo.app`).

**Windows** — nada a configurar: o login abre no navegador padrão e volta para `http://127.0.0.1:<porta>/bts`.

Outros apps .NET (WPF, console, Avalonia): use `Bts.Login.Cliente` com `new NavegadorRetornoLocal()`.

## 7. Regras para parceiros (resumo)

- Peça só os escopos de que precisa; diga na sua tela por que pede o celular ou os níveis.
- Use o `sub` como chave da conta (o e-mail pode mudar).
- Nunca peça a senha da BTS no seu site ou app: o login acontece sempre em `login.bellga.tech`.
- Use o botão oficial sem mudar cores, texto ou proporções (https://bellga.tech/marca.html).
- Os dados recebidos seguem a LGPD: use só para a finalidade informada à pessoa e apague quando ela pedir.

## Licença

Código sob a licença MIT (arquivo `LICENSE`). O nome BTS, o escudo e o botão "Entrar com BTS" são marcas da
Bellga Tech Solutions: use-os só como descrito em https://bellga.tech/marca.html.

## Desenvolvimento deste repositório

```bash
dotnet test bts-parceiros.slnx
```

O `Bts.Login.Maui` compila `net10.0` e `net10.0-android` em qualquer sistema com o workload `maui-android`;
`net10.0-windows` só no Windows e `net10.0-ios` só no Mac.
Publicar: suba a `<Version>` no `Directory.Build.props`, anote no `CHANGELOG.md` e crie a tag `vX.Y.Z`
(o workflow `publicar.yml` testa, empacota e envia ao nuget.org por Trusted Publishing).
