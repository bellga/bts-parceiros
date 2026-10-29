# Changelog

## 1.1.0
- `Bts.Login.AspNetCore`: **vínculo com contas existentes** (`AddVinculoBts<T>`, `IVinculoBts`). Conta já ligada entra direto; e-mail igual nunca liga sozinho: a pessoa entra uma vez pelo login antigo e confirma (cookie cifrado com prazo de 10 min, antifalsificação, conta diferente recusada); pessoa nova ganha conta. Rota `/vincular/bts/iniciar` para quem já está conectado; conta BTS ligada a outra conta não é tomada. Opção `VinculoAutomatico` (desligada por padrão). `User.ContaParceiro()` e a claim `bts_conta`.

## 1.0.1
- Publicação no **nuget.org** (Trusted Publishing, sem chave guardada), licença MIT, ícone, símbolos (`.snupkg`) com Source Link. Código igual ao da 1.0.0.

## 1.0.0
- `Bts.Login.AspNetCore`: `AddEntrarComBts`/`AddBts` (OpenID Connect com PKCE S256, resposta por query, claims com os nomes do OIDC, cancelar volta ao site), `MapEntrarComBts` (`/entrar/bts` com retorno só local e `/sair/bts` com antifalsificação), `AddBtsBearer` (só access token `at+jwt` dos ClientIds do parceiro), atalhos `User.IdBts()`/`NiveisBts()`/`TemNivelBts()`, política `ExigirNivelBts`, botão oficial (`<bts-botao>`, `BtsBotao.Html`, CSS em `_content`).
- `Bts.Login.Cliente`: `BtsCliente` (entrar, renovar, sair) com validação do id_token (assinatura, emissor, audiência, nonce, validade), state em tempo constante, conferência do `iss` da volta (RFC 9207), recusa de parâmetros repetidos; `NavegadorRetornoLocal` (127.0.0.1 com porta escolhida na hora).
- `Bts.Login.Maui`: `NavegadorMaui` (WebAuthenticator no Android/iOS, retorno local no Windows), `BtsLoginMaui.Criar` e o controle `BotaoBts`.
