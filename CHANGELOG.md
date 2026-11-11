# Changelog

## 1.2.0
- **Login recente para ações sensíveis** (a BTS passou a emitir `auth_time` e `amr` em 10/11/2026).
- `Bts.Login.AspNetCore`: política `ExigirLoginRecenteBts(limite, exigirSenha)` — no site leva a pessoa para a BTS com `max_age` (e `prompt=login` quando exige a senha) e volta para a mesma página; na API responde `401` com `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=...` (RFC 9470). Atalhos `User.AutenticadoEmBts()`, `FormasDeEntrarBts()`, `EntrouComSenhaBts()`, `LoginRecenteBts()`; claims `BtsClaims.AutenticadoEm`/`FormasDeEntrar` e `BtsFormasDeEntrar`. `/entrar/bts` aceita `&senha=1` e `&max_age=N`.
- `Bts.Login.Cliente`: `EntrarAsync(BtsOpcoesEntrar { PedirSenha, LoginRecente })` manda `prompt=login`/`max_age` e confere o `auth_time` na volta (`BtsException` com `Erro = insufficient_user_authentication`); `BtsCliente.PedeLoginRecente(resposta, out limite)` lê o 401 da API; `BtsPessoa.AutenticadoEm`, `FormasDeEntrar`, `EntrouComSenha`. `EntrarAsync(forcarSenha: true)` também confere o `auth_time`.

## 1.1.0
- `Bts.Login.AspNetCore`: **vínculo com contas existentes** (`AddVinculoBts<T>`, `IVinculoBts`). Conta já ligada entra direto; e-mail igual nunca liga sozinho: a pessoa entra uma vez pelo login antigo e confirma (cookie cifrado com prazo de 10 min, antifalsificação, conta diferente recusada); pessoa nova ganha conta. Rota `/vincular/bts/iniciar` para quem já está conectado; conta BTS ligada a outra conta não é tomada. Opção `VinculoAutomatico` (desligada por padrão). `User.ContaParceiro()` e a claim `bts_conta`.

## 1.0.1
- Publicação no **nuget.org** (Trusted Publishing, sem chave guardada), licença MIT, ícone, símbolos (`.snupkg`) com Source Link. Código igual ao da 1.0.0.

## 1.0.0
- `Bts.Login.AspNetCore`: `AddEntrarComBts`/`AddBts` (OpenID Connect com PKCE S256, resposta por query, claims com os nomes do OIDC, cancelar volta ao site), `MapEntrarComBts` (`/entrar/bts` com retorno só local e `/sair/bts` com antifalsificação), `AddBtsBearer` (só access token `at+jwt` dos ClientIds do parceiro), atalhos `User.IdBts()`/`NiveisBts()`/`TemNivelBts()`, política `ExigirNivelBts`, botão oficial (`<bts-botao>`, `BtsBotao.Html`, CSS em `_content`).
- `Bts.Login.Cliente`: `BtsCliente` (entrar, renovar, sair) com validação do id_token (assinatura, emissor, audiência, nonce, validade), state em tempo constante, conferência do `iss` da volta (RFC 9207), recusa de parâmetros repetidos; `NavegadorRetornoLocal` (127.0.0.1 com porta escolhida na hora).
- `Bts.Login.Maui`: `NavegadorMaui` (WebAuthenticator no Android/iOS, retorno local no Windows), `BtsLoginMaui.Criar` e o controle `BotaoBts`.
