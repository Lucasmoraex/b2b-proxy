# B2B Proxy — cadastro seguro v2

Backend de reserva e sincronização do cadastro B2B da Elements Para Empresas. A senha nunca faz parte dos contratos deste serviço: criação e autenticação continuam sendo feitas pela Shopify.

## Arquitetura

1. O tema reserva e-mail, CNPJ, telefone e faixa de colaboradores em `POST /v1/registrations`.
2. PostgreSQL garante unicidade atômica e idempotência.
   Quando habilitado, o índice HMAC de identidades históricas também bloqueia valores já associados a Customers existentes, sem guardar esses valores em texto puro.
   Novas reservas usam blind indexes HMAC para as três identidades e guardam o payload operacional, inclusive a faixa de colaboradores, criptografado com AES-256-GCM; as colunas legadas de PII permanecem `NULL`.
3. O tema só então submete o formulário nativo `create_customer` à Shopify.
4. O webhook `customers/create`, autenticado por HMAC, associa o `customer_id` à reserva.
5. O webhook grava uma operação na outbox e responde `202` sem chamar a Admin API.
6. O worker sincroniza telefone, metafields e tags por `customer_id` via GraphQL Admin API.
7. A conta termina em `pending_review`. Autoaprovação é desabilitada por padrão.
8. Aprovação/rejeição administrativa apenas enfileira operações idempotentes.

Estados: `reserved`, `pending_shopify`, `pending_validation`, `pending_review`, `approved`, `rejected`, `failed`, `expired`.

## Execução local

Requisitos: Node.js 18+, npm e PostgreSQL 16. O Compose fornecido contém somente PostgreSQL.

```sh
cp .env.example .env
docker compose up -d postgres
npm install
npm run migrate
npm start
```

Em outro processo:

```sh
npm run worker
```

Testes unitários e de contrato, sem rede externa:

```sh
npm test
npm run test:coverage
npm run check
```

Para incluir a suíte PostgreSQL, configure `TEST_DATABASE_URL` para um banco exclusivamente de testes. A suíte cria e remove somente um schema aleatório próprio.

O checklist completo de staging no Render, integração com uma única development store e execução do simulador está em [`docs/STAGING.md`](docs/STAGING.md).

A ferramenta GraphQL somente leitura para auditar Customers está documentada em [`docs/SHOPIFY_CUSTOMER_AUDIT.md`](docs/SHOPIFY_CUSTOMER_AUDIT.md). Ela não usa o banco da aplicação e grava somente um relatório local ignorado pelo Git.

O modelo, as travas e o rollout futuro do índice histórico estão em [`docs/HISTORICAL_IDENTITIES.md`](docs/HISTORICAL_IDENTITIES.md). Lookup e importação ficam desligados por padrão.

A máquina de estados de claims, criptografia e operação segura da retenção estão em [`docs/DATA_RETENTION.md`](docs/DATA_RETENTION.md). A retenção fica desabilitada e em `report-only` por padrão.

## Variáveis

Consulte `.env.example` e `docs/STAGING.md`. Compartilhadas pelo Web e Worker:

- `DATABASE_URL`

Obrigatórias no Web:

- `SHOPIFY_WEBHOOK_SECRET`
- `B2B_ADMIN_SECRET`
- `B2B_REGISTRATION_TOKEN_SECRET`
- `B2B_DATA_DIGEST_SECRET` (HMAC exclusivo, mínimo de 32 bytes)
- `B2B_PII_ENCRYPTION_ACTIVE_KEY_VERSION`
- `B2B_PII_ENCRYPTION_KEYS` (objeto JSON de versões para chaves AES-256-GCM em base64)
- `B2B_RATE_LIMIT_KEY_SECRET` (HMAC exclusivo, mínimo de 32 bytes)

Obrigatórias no Worker real:

- `SHOPIFY_SHOP`
- `SHOPIFY_CLIENT_ID` e `SHOPIFY_CLIENT_SECRET` (recomendado para store da mesma organização); ou `SHOPIFY_ADMIN_TOKEN` legado

Configuração adicional:

- `DATABASE_SSL`
- `SHOPIFY_API_VERSION`
- `B2B_ALLOWED_ORIGIN`
- `B2B_RECEITAWS_BASE`
- `B2B_RECEITAWS_TOKEN`
- `B2B_RECEITAWS_TOKEN_MODE`
- `B2B_REGISTRATION_TOKEN_CLOCK_TOLERANCE_MS` (padrão `1000`, máximo `5000`; expiração antecipada/fail-closed)
- `B2B_DATA_DIGEST_VERSION` (somente `hmac-sha256-v1`)
- `B2B_AUTO_APPROVE`
- `B2B_ENABLE_LEGACY_MUTATIONS`
- `B2B_ENABLE_LEGACY_LOGIN`
- `B2B_ENABLE_HISTORICAL_IDENTITY_LOOKUP` (padrão `false`)
- `B2B_IDENTITY_INDEX_SECRET` (chave exclusiva, mínimo de 32 bytes)
- `B2B_REQUEST_TIMEOUT_MS`
- `B2B_RESERVATION_TTL_MS`
- `B2B_FISCAL_CACHE_TTL_MS` (TTL do cache fiscal PostgreSQL; padrão: 24 horas; ignorado na simulação)
- `B2B_RATE_LIMIT_WINDOW_MS`
- `B2B_RATE_LIMIT_MAX`
- `B2B_SHARED_RATE_LIMIT_WINDOW_MS`
- `B2B_SHARED_RATE_LIMIT_MAX`
- `B2B_IDENTITY_RATE_LIMIT_WINDOW_MS`
- `B2B_IDENTITY_RATE_LIMIT_MAX`
- `B2B_ACTIVE_RESERVATIONS_PER_IP_MAX`
- `B2B_RATE_LIMIT_STATE_RETENTION_MS`
- `B2B_RATE_LIMIT_CLEANUP_BATCH_SIZE`
- `B2B_JSON_BODY_LIMIT_BYTES`
- `B2B_WEBHOOK_BODY_LIMIT_BYTES`
- `B2B_TRUST_PROXY_HOPS`
- `B2B_HEADER_TIMEOUT_MS`
- `B2B_HTTP_REQUEST_TIMEOUT_MS`
- `B2B_KEEP_ALIVE_TIMEOUT_MS`
- `B2B_WORKER_POLL_MS`
- `B2B_WORKER_MAX_ATTEMPTS`
- `B2B_RETENTION_ENABLED` (padrão `false`)
- `B2B_RETENTION_MODE` (padrão `report-only`)
- `B2B_RETENTION_EXPIRED_UNLINKED_MS`
- `B2B_RETENTION_SYNCED_PAYLOAD_MS`
- `B2B_RETENTION_FAILED_UNLINKED_MS`
- `B2B_RETENTION_OPERATIONAL_EVENTS_MS`
- `B2B_RETENTION_BATCH_SIZE`
- `B2B_RETENTION_CONFIRMATION` (somente execução)
- `B2B_ALLOW_PRODUCTION_RETENTION` (padrão `false`)
- `B2B_ENVIRONMENT`
- `B2B_SIMULATION_MODE`
- `B2B_SIMULATION_CONFIRMATION`
- `B2B_SIMULATED_REGISTRY_SCENARIO`
- `PORT`

## `POST /v1/registrations`

Headers:

```text
Content-Type: application/json
Idempotency-Key: UUID
```

Body permitido — campos adicionais, inclusive `password`, são rejeitados:

```json
{
  "email": "empresa@example.invalid",
  "cnpj": "CNPJ sintético válido",
  "phone": "+55NUMERO_SINTETICO",
  "employee_range": "10-29"
}
```

`employee_range` é obrigatório e aceita somente `1-9`, `10-29`, `30-49`, `50-99`, `100-249` ou `250+`. O endpoint normaliza o e-mail, valida o CNPJ, normaliza telefone brasileiro para E.164, valida a faixa, consulta a situação fiscal e cria na mesma transação a reservation, três blind indexes e o payload operacional criptografado. A faixa participa do digest de idempotência, mas não cria claim, unicidade ou rate limit por identidade. O endpoint não pesquisa nem altera Customer Shopify. E-mail, CNPJ, telefone e faixa de novas reservations não são gravados em texto puro na linha de `registrations`.

A ordem é: idempotência, admissão/quota compartilhada, conflitos em reservas atuais, conflito opcional no snapshot histórico ativo, cache/consulta fiscal e reserva `SERIALIZABLE`. Claims históricos únicos ou duplicados usam os mesmos códigos públicos de conflito e impedem a chamada fiscal. Se o lookup histórico estiver habilitado sem um `active_import_run_id` concluído, o cadastro falha fechado com `503 identity_index_unavailable`; runs `staging` ou `failed` nunca participam do lookup.

Sucesso `201`:

```json
{
  "ok": true,
  "registration_id": "00000000-0000-4000-8000-000000000000",
  "registration_token": "token-opaco-assinado",
  "status": "reserved",
  "expires_at": "2030-01-01T00:30:00.000Z"
}
```

Erros têm formato genérico:

```json
{
  "ok": false,
  "error": {
    "code": "invalid_cnpj",
    "message": "Request could not be completed."
  }
}
```

Status/códigos:

- `409 email_in_use`
- `409 cnpj_in_use`
- `409 phone_in_use`
- `409 idempotency_conflict`
- `422 invalid_email`
- `422 invalid_cnpj`
- `422 invalid_phone`
- `422 invalid_employee_range`
- `422 inactive_cnpj`
- `422 invalid_request`
- `403 origin_required` (produção sem `Origin` no cadastro)
- `413 payload_too_large`
- `415 unsupported_media_type`
- `429 rate_limited`
- `503 identity_index_unavailable` (quando o lookup histórico está habilitado sem snapshot ativo válido)
- `503 registry_unavailable`
- `500 internal_error`

A repetição da mesma chave e mesmo payload retorna o mesmo registro, inclusive depois do purge do payload quando a registration já está vinculada. A mesma chave com payload normalizado diferente retorna `idempotency_conflict`. Uma reserva expirada e ainda não vinculada libera atomicamente seus claims; a linha mínima permanece como evidência operacional.

Exemplo propositalmente inválido, sem dado real:

```sh
curl -X POST http://localhost:3000/v1/registrations \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: 00000000-0000-4000-8000-000000000001' \
  --data '{"email":"empresa@example.invalid","cnpj":"00000000000000","phone":"+5500000000000","employee_range":"10-29"}'
```

## Consulta de processamento

```http
GET /v1/registrations/:id
Authorization: Bearer <registration_token>
```

Retorna somente `registration_id`, `status` e `expires_at`; não retorna PII. O token deixa de ser aceito no limite exato de `expires_at`; a tolerância configurável é aplicada de forma conservadora e pode antecipar a expiração, nunca prolongá-la. Registration inexistente, token inválido e token expirado retornam o mesmo `401 unauthorized` genérico. O tema deve usar esta rota para mostrar processamento pendente/falha em vez de ignorar o resultado do backend.

## Webhook Shopify

```http
POST /webhooks/shopify/customers-create
X-Shopify-Hmac-Sha256: <HMAC base64 do corpo bruto>
X-Shopify-Webhook-Id: <id único da entrega>
X-Shopify-Topic: customers/create
X-Shopify-Shop-Domain: store-name.example.invalid
```

O HMAC SHA-256 é calculado sobre o corpo bruto e comparado em tempo constante. A idempotência prioriza `X-Shopify-Webhook-Id`; `X-Shopify-Event-Id` é aceito como compatibilidade. Caso ambos faltem, a chave determinística é `topic + shop domain + customer id`; para `customers/create`, o customer ID torna essa chave estável.

Resposta `202`:

```json
{
  "ok": true,
  "accepted": true,
  "duplicate": false,
  "matched": true
}
```

O webhook compara o e-mail normalizado exatamente, associa o ID dentro da transação, grava a outbox e não chama a Shopify durante a requisição.

Exemplo de HMAC inválido e payload fictício:

```sh
curl -X POST http://localhost:3000/webhooks/shopify/customers-create \
  -H 'Content-Type: application/json' \
  -H 'X-Shopify-Hmac-Sha256: invalid' \
  --data '{"id":"synthetic-customer","email":"empresa@example.invalid"}'
```

## Administração

Somente `POST`, com `X-B2B-Admin-Secret`. Secret em query string não é aceito.

- `POST /admin/approve`
- `POST /admin/reject`
- `POST /admin/reconcile`

Alvo:

```json
{ "registration_id": "00000000-0000-4000-8000-000000000000" }
```

Approve/reject também aceitam `shopify_customer_id`; reconciliação exige `registration_id`. Aprovação só é enfileirada após CNPJ ativo, vínculo por customer ID e sincronização concluída. A conclusão no banco ocorre apenas depois de metafield e tag convergirem no worker.

## Endpoints legados

- `/register-cnpj`: `410` por padrão; se habilitado, ainda exige secret no header.
- `/validate-cnpj`: `410` por padrão; se habilitado, exige secret e somente consulta a situação fiscal, sem alterar Customer.
- `/validate-login`: permanentemente `410`; o login deve conter apenas e-mail e senha e permanecer nativo da Shopify.
- variantes GET de approve/reject: removidas.
- `/precheck-cnpj`: continua público e somente leitura para transição; `/v1/registrations` já incorpora essa validação.

## Contrato do tema Shopify

1. Gerar um UUID para `Idempotency-Key` e preservá-lo durante retries do mesmo envio.
2. Enviar somente `email`, `cnpj`, `phone` e `employee_range` a `/v1/registrations` e aguardar a resposta.
3. Em erro, não submeter `create_customer`; mapear o `error.code` para uma mensagem amigável.
4. Em `201`, guardar temporariamente `registration_id` e `registration_token` no `sessionStorage` e então submeter o formulário nativo Shopify com e-mail e senha. O proxy nunca recebe a senha.
5. Não chamar `/register-cnpj`, `/validate-cnpj` ou `/validate-login`.
6. Consultar o status autenticado para exibir processamento pendente/falha.
7. Após login nativo, liberar B2B somente quando o Customer autenticado tiver simultaneamente `b2b-approved`, `custom.cnpj` e `custom.cnpj_status == approved`.
8. Redirecionar `pending`, `rejected` e `failed` para páginas adequadas sem expor estado de outras contas.
9. Remover imediatamente `registration_id` e `registration_token` do `sessionStorage` quando o status for terminal (`approved`, `rejected`, `failed` ou `expired`), quando o relógio atingir `expires_at`, ou quando a consulta retornar `401 unauthorized`. Não copiar esses valores para `localStorage`, query string, analytics ou logs.

## Segurança operacional

Logs estruturados usam allowlist de campos escalares e não aceitam objetos `Error`, headers, URLs, arrays ou contexto arbitrário. As mensagens externas não incluem stack, SQL ou resposta de provedores. Requests de cadastro, payloads de webhook e admissões usam HMAC SHA-256 versionado com separação de domínio e `B2B_DATA_DIGEST_SECRET`; digests legados não recebem backfill automático. Consulte [`docs/PRIVACY_LIFECYCLE.md`](docs/PRIVACY_LIFECYCLE.md) e [`docs/PRODUCTION_HARDENING.md`](docs/PRODUCTION_HARDENING.md).
