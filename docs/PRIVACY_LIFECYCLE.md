# Privacidade crítica e ciclo de vida

As proteções de token, digests e logs abaixo são complementadas pela minimização e retenção documentadas em [`DATA_RETENTION.md`](DATA_RETENTION.md). Webhooks de privacidade continuam fora desta etapa e nenhuma rotina de limpeza é habilitada automaticamente.

## Token de registration

`GET /v1/registrations/:id` aceita o token somente quando:

- a assinatura corresponde ao ID e ao `expires_at` persistido;
- a hora injetada ainda está antes de `expires_at`;
- a margem `B2B_REGISTRATION_TOKEN_CLOCK_TOLERANCE_MS` também cabe antes da expiração.

A margem é fail-closed: o token pode expirar ligeiramente antes, nunca depois. O padrão é `1000` ms, o máximo é `5000` ms e a borda exata de `expires_at` já é inválida. Registration inexistente, assinatura inválida, secret rotacionado, ID diferente, expiração alterada e token expirado retornam o mesmo `401 unauthorized` com mensagem genérica.

Contrato do tema: guardar `registration_id` e `registration_token` somente no `sessionStorage`. Apagar ambos ao receber estado terminal (`approved`, `rejected`, `failed`, `expired`), ao alcançar `expires_at` localmente ou ao receber `401`. Não persistir em `localStorage`, URL, analytics ou logs.

## Digests de dados

Novas escritas usam `hmac-sha256-v1` e `B2B_DATA_DIGEST_SECRET`, com separação de domínio:

- `registration-request:v1`;
- `webhook-payload:v1`;
- `rate-limit-admission:v1`.

O secret deve ter no mínimo 32 bytes e ser diferente dos secrets administrativo, registration token, webhook, rate limit, índice histórico e credenciais externas. Produção recusa inicialização sem o secret ou com versão desconhecida. As colunas de versão são nullable apenas para distinguir linhas legadas; não existe backfill automático.

## Logs e erros persistidos

O logger aceita somente escalares validados nos campos:

- `requestId`, `method`, `path`, `status`, `elapsedMs`;
- `operation`, `code`, `category`, `attempt`, `attempts`, `terminal`;
- `durationMs`, `delayMs`, `reason`, `port`, `importStatus`, `action`.

Campos desconhecidos, objetos aninhados, arrays, `Error`, URLs e valores fora do formato permitido são descartados silenciosamente. `path` deve ser o template Express, sem query string.

Novas falhas da outbox e de imports históricos gravam somente `error_code`, `error_category`, `upstream_status` opcional e `error_recorded_at`. `last_error` permanece no schema para compatibilidade, mas novas escritas sempre o deixam `NULL`.

## ReceitaWS

`B2B_RECEITAWS_TOKEN_MODE` aceita somente:

- `bearer`: token opcional enviado em `Authorization: Bearer`;
- `none`: exige `B2B_RECEITAWS_TOKEN` vazio.

Token em query string é recusado durante a inicialização. O contrato fiscal de `found`, `active`, `status` e timeout permanece inalterado.
