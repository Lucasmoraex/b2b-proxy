# B2B Proxy — cadastro seguro v2

Backend de reserva e sincronização do cadastro B2B da Elements Para Empresas. A senha nunca faz parte dos contratos deste serviço: criação e autenticação continuam sendo feitas pela Shopify.

## Arquitetura

1. O tema reserva e-mail, CNPJ e telefone em `POST /v1/registrations`.
2. PostgreSQL garante unicidade atômica e idempotência.
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

## Variáveis

Consulte `.env.example`. Obrigatórias para a aplicação completa:

- `DATABASE_URL`
- `SHOPIFY_SHOP`
- `SHOPIFY_ADMIN_TOKEN`
- `SHOPIFY_WEBHOOK_SECRET`
- `B2B_ADMIN_SECRET`
- `B2B_REGISTRATION_TOKEN_SECRET`

Configuração adicional:

- `DATABASE_SSL`
- `SHOPIFY_API_VERSION`
- `B2B_ALLOWED_ORIGIN`
- `B2B_RECEITAWS_BASE`
- `B2B_RECEITAWS_TOKEN`
- `B2B_RECEITAWS_TOKEN_MODE`
- `B2B_AUTO_APPROVE`
- `B2B_ENABLE_LEGACY_MUTATIONS`
- `B2B_ENABLE_LEGACY_LOGIN`
- `B2B_REQUEST_TIMEOUT_MS`
- `B2B_RESERVATION_TTL_MS`
- `B2B_RATE_LIMIT_WINDOW_MS`
- `B2B_RATE_LIMIT_MAX`
- `B2B_WORKER_POLL_MS`
- `B2B_WORKER_MAX_ATTEMPTS`
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
  "phone": "+55NUMERO_SINTETICO"
}
```

O endpoint normaliza o e-mail, valida o CNPJ, normaliza telefone brasileiro para E.164, consulta a situação fiscal e cria a reserva em uma transação. Ele não pesquisa nem altera Customer Shopify.

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
- `422 inactive_cnpj`
- `422 invalid_request`
- `429 rate_limited`
- `503 registry_unavailable`
- `500 internal_error`

A repetição da mesma chave e mesmo payload retorna o mesmo registro. A mesma chave com payload normalizado diferente retorna `idempotency_conflict`. Uma reserva expirada e ainda não vinculada é removida atomicamente e libera seus valores.

Exemplo propositalmente inválido, sem dado real:

```sh
curl -X POST http://localhost:3000/v1/registrations \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: 00000000-0000-4000-8000-000000000001' \
  --data '{"email":"empresa@example.invalid","cnpj":"00000000000000","phone":"+5500000000000"}'
```

## Consulta de processamento

```http
GET /v1/registrations/:id
Authorization: Bearer <registration_token>
```

Retorna somente `registration_id`, `status` e `expires_at`; não retorna PII. O tema deve usar esta rota para mostrar processamento pendente/falha em vez de ignorar o resultado do backend.

## Webhook Shopify

```http
POST /webhooks/shopify/customers-create
X-Shopify-Hmac-Sha256: <HMAC base64 do corpo bruto>
X-Shopify-Event-Id: <id único>
X-Shopify-Topic: customers/create
X-Shopify-Shop-Domain: store-name.example.invalid
```

O HMAC SHA-256 é calculado sobre o corpo bruto e comparado em tempo constante. A idempotência usa `X-Shopify-Event-Id`. Caso esse header não esteja presente, a chave determinística é `topic + shop domain + customer id`; para `customers/create`, o customer ID torna essa chave estável.

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
2. Enviar somente `email`, `cnpj` e `phone` a `/v1/registrations` e aguardar a resposta.
3. Em erro, não submeter `create_customer`; mapear o `error.code` para uma mensagem amigável.
4. Em `201`, guardar temporariamente `registration_id` e `registration_token` e então submeter o formulário nativo Shopify com e-mail e senha. O proxy nunca recebe a senha.
5. Não chamar `/register-cnpj`, `/validate-cnpj` ou `/validate-login`.
6. Consultar o status autenticado para exibir processamento pendente/falha.
7. Após login nativo, liberar B2B somente quando o Customer autenticado tiver simultaneamente `b2b-approved`, `custom.cnpj` e `custom.cnpj_status == approved`.
8. Redirecionar `pending`, `rejected` e `failed` para páginas adequadas sem expor estado de outras contas.

## Segurança operacional

Logs estruturados não incluem query string, body, e-mail, CNPJ, telefone, secret, token ou valor de metafield. As mensagens externas não incluem stack, SQL ou resposta de provedores. O rate limit atual é em memória; produção com múltiplas instâncias deve usar um store compartilhado antes do rollout horizontal.
