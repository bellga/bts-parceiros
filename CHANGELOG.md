# Changelog

## 1.0.1
- Publicação no **nuget.org** (Trusted Publishing, sem chave guardada), licença MIT, ícone, símbolos (`.snupkg`) com Source Link. Código igual ao da 1.0.0.

## 1.0.0
- `Bts.Login.AspNetCore`: `AddEntrarComBts`/`AddBts` (OpenID Connect com PKCE S256, resposta por query, claims com os nomes do OIDC, cancelar volta ao site), `MapEntrarComBts` (`/entrar/bts` com retorno só local e `/sair/bts` com antifalsificação), `AddBtsBearer` (só access token `at+jwt` dos ClientIds do parceiro), atalhos `User.IdBts()`/`NiveisBts()`/`TemNivelBts()`, política `ExigirNivelBts`, botão oficial (`<bts-botao>`, `BtsBotao.Html`, CSS em `_content`).
- `Bts.Login.Cliente`: `BtsCliente` (entrar, renovar, sair) com validação do id_token (assinatura, emissor, audiência, nonce, validade), state em tempo constante, conferência do `iss` da volta (RFC 9207), recusa de parâmetros repetidos; `NavegadorRetornoLocal` (127.0.0.1 com porta escolhida na hora).
- `Bts.Login.Maui`: `NavegadorMaui` (WebAuthenticator no Android/iOS, retorno local no Windows), `BtsLoginMaui.Criar` e o controle `BotaoBts`.
