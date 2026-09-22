# Staging v2 — Render, simulador e Shopify development store

Este runbook descreve um ambiente novo e isolado. Ele não reutiliza banco, serviços, env groups, domínio, app Shopify ou secrets de produção. Criar um serviço no Render inicia o primeiro deploy; portanto, as etapas marcadas **AUTORIZAÇÃO EXTERNA** não devem ser executadas sem aprovação explícita.

## 1. Topologia e ordem segura

Crie um Project/Environment de staging separado e use nomes que contenham literalmente `staging`:

- PostgreSQL: `elements-b2b-v2-staging-db`;
- Web Service: `elements-b2b-v2-staging-api`;
- Background Worker: `elements-b2b-v2-staging-worker`.

Todos devem ficar na mesma região. Não vincule env groups usados por produção. O Web recebe HTTP; o Worker não recebe tráfego e apenas consome a outbox PostgreSQL.

Ordem recomendada:

1. Obter autorização para fazer push da branch de staging.
2. Fazer o push sem tocar na branch de produção.
3. Criar o PostgreSQL separado.
4. Criar Web e Worker com **Auto-Deploy = Off**.
5. Configurar secrets exclusivos de staging.
6. Rodar `npm run migrate` uma única vez pelo Web.
7. Validar primeiro em simulação isolada.
8. Somente após nova autorização, instalar/conectar o app a uma única development store e trocar para o perfil de integração real.

## 2. PostgreSQL no Render

No Dashboard: **New > Postgres**.

- Name: `elements-b2b-v2-staging-db`.
- PostgreSQL: versão 16 ou outra versão atualmente suportada e compatível.
- Region: a mesma do Web e Worker.
- Database/User: exclusivos de staging.
- Networking: desabilitar acesso externo quando não for necessário.
- Conexão dos serviços: usar a **Internal Database URL**, nunca a URL do banco de produção.

Defina a Internal Database URL como `DATABASE_URL` no Web e Worker. Com a rede privada atual, configure `DATABASE_SSL=false`; o código atual usa verificação estrita de certificado quando `DATABASE_SSL=true`, enquanto o TLS interno do Render usa certificado autoassinado. Isso deve ser revisto antes de exigir TLS na rede privada.

### Migration

Comando único:

```sh
npm run migrate
```

Configuração recomendada: no Web Service, **Pre-Deploy Command = `npm run migrate`**. Não configure o mesmo pre-deploy no Worker, para evitar duas instâncias migrando simultaneamente. Pre-deploy commands dependem do plano do Render; se o plano não oferecer esse recurso, rode o comando manualmente no Shell do Web antes de iniciar o Worker. As migrations são registradas em `schema_migrations`.

## 3. Web Service no Render

No Dashboard: **New > Web Service** e selecione somente a branch `feat/secure-b2b-registration-v2`.

- Name: `elements-b2b-v2-staging-api`.
- Runtime: Node.
- Build Command: `npm ci`.
- Pre-Deploy Command: `npm run migrate` (se disponível no plano).
- Start Command: `npm start`.
- Health Check Path: `/health`.
- Auto-Deploy: **Off** antes de qualquer push posterior.
- `PORT`: não precisa ser criado manualmente; o Render fornece o valor.

O Web não precisa de credencial para a Admin API da Shopify. Ele recebe reservas e webhook, valida o HMAC e grava PostgreSQL/outbox.

## 4. Background Worker no Render

No Dashboard: **New > Background Worker**, usando a mesma branch.

- Name: `elements-b2b-v2-staging-worker`.
- Runtime: Node.
- Build Command: `npm ci`.
- Pre-Deploy Command: vazio.
- Start Command: `npm run worker`.
- Auto-Deploy: **Off**.

O Worker não precisa de `PORT`, webhook secret, admin secret, token de registration, CORS ou credencial ReceitaWS. No perfil real, somente ele recebe as credenciais GraphQL da Shopify.

## 5. Variáveis por serviço

Use valores aleatórios diferentes dos de produção. Nunca cole valores no Git, em tickets ou em comandos que fiquem no histórico do shell.

### Web — comuns aos dois perfis

| Variável | Valor/uso |
| --- | --- |
| `B2B_ENVIRONMENT` | `staging` |
| `DATABASE_URL` | Internal Database URL do PostgreSQL de staging |
| `DATABASE_SSL` | `false` para a conexão privada descrita acima |
| `B2B_ADMIN_SECRET` | secret aleatório exclusivo de staging |
| `B2B_REGISTRATION_TOKEN_SECRET` | secret aleatório exclusivo de staging |
| `SHOPIFY_WEBHOOK_SECRET` | perfil real: secret que assina o webhook; simulação: secret exclusivo iniciado por `sim_` |
| `B2B_ALLOWED_ORIGIN` | origem HTTPS exata do tema de teste; lista separada por vírgula se necessário |
| `B2B_AUTO_APPROVE` | `false` |
| `B2B_ENABLE_LEGACY_MUTATIONS` | `false` |
| `B2B_ENABLE_LEGACY_LOGIN` | `false` |
| `B2B_REQUEST_TIMEOUT_MS` | por exemplo `8000` |
| `B2B_RESERVATION_TTL_MS` | por exemplo `1800000` |
| `B2B_RATE_LIMIT_WINDOW_MS` | por exemplo `60000` |
| `B2B_RATE_LIMIT_MAX` | por exemplo `30` |

### Web — perfil de simulação isolada

| Variável | Valor |
| --- | --- |
| `NODE_ENV` | `development` |
| `B2B_SIMULATION_MODE` | `true` |
| `B2B_SIMULATION_CONFIRMATION` | `ENABLE_ISOLATED_SIMULATION` |
| `B2B_SIMULATED_REGISTRY_SCENARIO` | `active`, `inactive` ou `unavailable` |
| `SHOPIFY_SHOP` | `simulation.example.invalid` |
| `SHOPIFY_ADMIN_TOKEN` | ausente/vazio |
| `SHOPIFY_CLIENT_ID` | ausente/vazio |
| `SHOPIFY_CLIENT_SECRET` | ausente/vazio |
| `B2B_RECEITAWS_TOKEN` | ausente/vazio |

`B2B_RECEITAWS_BASE` pode ficar ausente: o simulador não realiza fetch.

### Web — perfil real limitado à development store

| Variável | Valor/uso |
| --- | --- |
| `NODE_ENV` | `production` |
| `B2B_SIMULATION_MODE` | `false` |
| `SHOPIFY_SHOP` | domínio exato `nome-da-development-store.myshopify.com` |
| `B2B_RECEITAWS_BASE` | endpoint fiscal contratado |
| `B2B_RECEITAWS_TOKEN` | token de staging, se exigido pelo provedor |
| `B2B_RECEITAWS_TOKEN_MODE` | `bearer` ou o modo contratado |

Não configure `SHOPIFY_CLIENT_SECRET`, `SHOPIFY_CLIENT_ID` nem `SHOPIFY_ADMIN_TOKEN` no Web. `SHOPIFY_WEBHOOK_SECRET` é suficiente para verificar entregas.

### Worker — comuns

| Variável | Valor/uso |
| --- | --- |
| `B2B_ENVIRONMENT` | `staging` |
| `DATABASE_URL` | mesma Internal Database URL de staging |
| `DATABASE_SSL` | `false` para a conexão privada descrita acima |
| `B2B_AUTO_APPROVE` | `false` |
| `B2B_ENABLE_LEGACY_MUTATIONS` | `false` |
| `B2B_WORKER_POLL_MS` | por exemplo `2000` |
| `B2B_WORKER_MAX_ATTEMPTS` | por exemplo `8` |
| `B2B_REQUEST_TIMEOUT_MS` | por exemplo `8000` |

### Worker — perfil de simulação isolada

| Variável | Valor |
| --- | --- |
| `NODE_ENV` | `development` |
| `B2B_SIMULATION_MODE` | `true` |
| `B2B_SIMULATION_CONFIRMATION` | `ENABLE_ISOLATED_SIMULATION` |
| `SHOPIFY_SHOP` | `simulation.example.invalid` |
| `SHOPIFY_ADMIN_TOKEN` | ausente/vazio |
| `SHOPIFY_CLIENT_ID` | ausente/vazio |
| `SHOPIFY_CLIENT_SECRET` | ausente/vazio |
| `B2B_RECEITAWS_TOKEN` | ausente/vazio |

### Worker — perfil real limitado à development store

| Variável | Valor/uso |
| --- | --- |
| `NODE_ENV` | `production` |
| `B2B_SIMULATION_MODE` | `false` |
| `SHOPIFY_SHOP` | domínio exato da development store |
| `SHOPIFY_CLIENT_ID` | client ID do app instalado nessa store |
| `SHOPIFY_CLIENT_SECRET` | client secret do app instalado nessa store |
| `SHOPIFY_API_VERSION` | versão estável suportada, atualmente `2026-07` |
| `SHOPIFY_ADMIN_TOKEN` | ausente; apenas fallback legado, não recomendado |

O cliente troca client ID/secret por access token de curta duração e mantém cache com renovação antecipada. Não configure simultaneamente token estático e client credentials.

### Guardas do simulador

O processo recusa iniciar em simulação se qualquer condição abaixo falhar:

- `B2B_ENVIRONMENT` não é `development`, `staging` ou `test`;
- `NODE_ENV=production`;
- a frase de confirmação não coincide exatamente;
- há token ReceitaWS ou qualquer credencial Shopify;
- `SHOPIFY_SHOP` não termina em `.invalid`;
- o webhook secret do Web não começa com `sim_`;
- autoaprovação ou mutações legadas estão habilitadas;
- no Render, o nome do serviço não contém `staging`.

Essas travas são cumulativas e fail-closed. O simulador não faz chamadas a Shopify nem ReceitaWS; o estado Shopify sintético fica em `simulation_shopify_customers` no PostgreSQL de staging.

## 6. Uma única Shopify development store

Não use a store de produção.

1. No Shopify Dev Dashboard, crie uma development store dedicada no mesmo Organization do app.
2. Crie/seleciona um app exclusivo para esse staging e escolha distribuição compatível com uso interno.
3. Declare somente `write_customers`. Esse scope permite as mutações `customerUpdate`, `metafieldsSet`, `tagsAdd` e `tagsRemove`; ele inclui a leitura de customers necessária ao worker. O tópico `CUSTOMERS_CREATE` exige `read_customers`, já coberto por `write_customers`.
4. Em Protected customer data, selecione somente Customer e os campos Email e Phone. Email é necessário para correlacionar o webhook à reserva; Phone é necessário para sincronizar o campo oficial. Em development store, a Shopify permite uso em desenvolvimento após a seleção, sem revisão pública.
5. Instale o app somente nessa development store. Confirme que app e store pertencem ao mesmo Organization, requisito do client credentials grant.
6. Copie client ID/secret para o Worker de staging, nunca para o tema e nunca para produção.
7. Configure `SHOPIFY_SHOP` com o domínio `.myshopify.com` exato. Não use domínio customizado.

O backend nunca cria o Customer. O tema cria uma conta sintética na development store; o webhook entrega o ID e o worker passa a operar exclusivamente por esse ID.

## 7. Registrar `customers/create`

Callback:

```text
https://URL-STAGING/webhooks/shopify/customers-create
```

O script local `npm run shopify:webhook:register` usa `webhookSubscriptionCreate` com o tópico GraphQL `CUSTOMERS_CREATE`. Ele se recusa a executar sem staging não simulado, confirmação explícita, domínio da store confirmado e callback HTTPS cujo hostname contenha `staging`.

Variáveis temporárias, somente para executar o script em um terminal seguro:

- `B2B_ENVIRONMENT=staging`
- `B2B_SIMULATION_MODE=false`
- `SHOPIFY_SHOP`
- `SHOPIFY_CLIENT_ID`
- `SHOPIFY_CLIENT_SECRET`
- `SHOPIFY_API_VERSION=2026-07`
- `SHOPIFY_WEBHOOK_CALLBACK_URL=https://URL-STAGING/webhooks/shopify/customers-create`
- `B2B_CONFIRMED_DEVELOPMENT_STORE_DOMAIN` igual exatamente a `SHOPIFY_SHOP`
- `B2B_SHOPIFY_SETUP_CONFIRMATION=REGISTER_DEVELOPMENT_STORE_WEBHOOK`

Comando:

```sh
npm run shopify:webhook:register
```

Isso cria estado externo na development store e, portanto, exige autorização antes de rodar. Não coloque as três variáveis de setup no ambiente persistente dos serviços.

### `SHOPIFY_WEBHOOK_SECRET`

Use o client secret do app que criou a subscription. Configure-o somente no Web como `SHOPIFY_WEBHOOK_SECRET`; não é um token de Admin API. A Shopify calcula `X-Shopify-Hmac-Sha256` como HMAC SHA-256 do corpo bruto, codificado em Base64. Durante rotação, a Shopify documenta que assina com o client secret não revogado mais antigo; mantenha o Web alinhado ao secret que efetivamente assina até concluir/revogar a rotação.

## 8. Teste sintético do webhook com HMAC válido

Primeiro crie uma reserva em modo simulado. O CNPJ abaixo é apenas uma fixture matematicamente válida, nunca consultada externamente pelo simulador, e o domínio de e-mail é reservado para exemplos:

```sh
curl --request POST 'https://b2b-v2-staging.example.invalid/v1/registrations' \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: 00000000-0000-4000-8000-000000000101' \
  --data-binary '{"email":"b2b-staging@example.invalid","cnpj":"99.999.999/9999-62","phone":"+5511999990001"}'
```

Em um checkout local com `.env` de simulação (não commitado), gere uma requisição assinada sem imprimir o secret:

```sh
npm run simulation:webhook:fixture -- 'https://b2b-v2-staging.example.invalid/webhooks/shopify/customers-create'
```

O comando imprime um `curl` com corpo fictício, HMAC válido e `X-Shopify-Webhook-Id` aleatório. Troque somente o hostname `.invalid` pelo hostname real de staging depois de receber autorização. Não reformate o JSON após gerar o HMAC: qualquer byte diferente invalida a assinatura.

Resposta esperada:

```json
{"ok":true,"accepted":true,"duplicate":false,"matched":true}
```

Repetir o mesmo `X-Shopify-Webhook-Id` retorna `duplicate:true`. A idempotência prioriza esse header oficial; `X-Shopify-Event-Id` é apenas fallback de compatibilidade.

## 9. Cenários do simulador

O cenário fiscal pode ser alterado em runtime somente com o admin secret:

```sh
curl --request POST 'https://b2b-v2-staging.example.invalid/admin/simulation/registry' \
  --header 'Content-Type: application/json' \
  --header 'X-B2B-Admin-Secret: <SECRET-DE-STAGING>' \
  --data-binary '{"scenario":"inactive"}'
```

Valores: `active`, `inactive`, `unavailable`.

- Cadastro aceito: `active` + campos novos.
- CNPJ/e-mail/telefone duplicado: repita somente o campo desejado com nova `Idempotency-Key`; o PostgreSQL retorna respectivamente `cnpj_in_use`, `email_in_use`, `phone_in_use`.
- CNPJ inativo: selecione `inactive`; a API retorna `422 inactive_cnpj` sem reserva.
- ReceitaWS indisponível: selecione `unavailable`; retorna `503 registry_unavailable` sem reserva.
- Webhook: use a fixture assinada acima.
- Worker: o Background Worker consome `sync_registration` e cria estado sintético local.
- Aprovação: aguarde `pending_review`, chame `/admin/approve` por `registration_id` e aguarde o worker.

## 10. Aprovar/rejeitar sem PII real

Use apenas o UUID retornado pela reserva sintética:

```sh
curl --request POST 'https://b2b-v2-staging.example.invalid/admin/approve' \
  --header 'Content-Type: application/json' \
  --header 'X-B2B-Admin-Secret: <SECRET-DE-STAGING>' \
  --data-binary '{"registration_id":"00000000-0000-4000-8000-000000000000"}'
```

```sh
curl --request POST 'https://b2b-v2-staging.example.invalid/admin/reject' \
  --header 'Content-Type: application/json' \
  --header 'X-B2B-Admin-Secret: <SECRET-DE-STAGING>' \
  --data-binary '{"registration_id":"00000000-0000-4000-8000-000000000000"}'
```

Não use e-mail como alvo. Aprovar enfileira `approve_registration`; rejeitar enfileira `reject_registration` quando já existe vínculo Shopify. Ambos convergem somente quando o Worker processa a outbox.

## 11. Verificações ponta a ponta

### API

```sh
curl 'https://b2b-v2-staging.example.invalid/health'
```

Deve retornar `{"ok":true}`. Para consultar uma registration sem PII:

```sh
curl 'https://b2b-v2-staging.example.invalid/v1/registrations/00000000-0000-4000-8000-000000000000' \
  --header 'Authorization: Bearer <REGISTRATION-TOKEN-RETORNADO>'
```

### Banco, webhook, outbox e status

Use o Shell do Render ou uma conexão temporariamente allowlisted. As consultas abaixo não selecionam e-mail, CNPJ nem telefone:

```sql
SELECT id, shopify_customer_id, status, fiscal_status,
       sync_completed_at, expires_at, created_at, updated_at
FROM registrations
WHERE id = '00000000-0000-4000-8000-000000000000';

SELECT event_id, topic, payload_digest, processed_at
FROM webhook_events
ORDER BY processed_at DESC
LIMIT 10;

SELECT id, registration_id, operation, attempts, next_attempt_at,
       processed_at, last_error, locked_at
FROM outbox
WHERE registration_id = '00000000-0000-4000-8000-000000000000'
ORDER BY created_at;
```

Critérios:

- webhook válido: uma linha em `webhook_events` e `shopify_customer_id` associado;
- worker saudável: outbox com `processed_at` preenchido e sem lock abandonado;
- retry: `attempts` cresce, `next_attempt_at` vai ao futuro e `last_error` permanece sanitizado;
- sincronização: `registration.status=pending_review` e `sync_completed_at` preenchido;
- aprovação: após worker, `registration.status=approved`;
- rejeição: após worker, `registration.status=rejected`.

### Shopify simulada

```sh
curl 'https://b2b-v2-staging.example.invalid/admin/simulation/shopify/synthetic-customer-staging' \
  --header 'X-B2B-Admin-Secret: <SECRET-DE-STAGING>'
```

Confirme `phone`, `metafields.nodes` (`cnpj`, `cnpj_status`, campos fiscais) e `tags`. Também é possível consultar sem PII:

```sql
SELECT customer_id, tags, metafields->'cnpj_status' AS cnpj_status, updated_at
FROM simulation_shopify_customers
WHERE customer_id = 'synthetic-customer-staging';
```

### Shopify development store real

Depois de autorização e usando exclusivamente o Customer sintético criado nessa development store, confira no Admin:

- telefone oficial em E.164;
- `custom.cnpj`;
- `custom.cnpj_status`;
- `b2b-pending` após sync;
- ausência de `b2b-approved` antes da aprovação;
- `b2b-approved` e `custom.cnpj_status=approved` depois da aprovação;
- remoção de `b2b-approved` depois da rejeição.

Nunca faça essa inspeção na store de produção.

## 12. Teste PostgreSQL que fica skipped

Suba somente o PostgreSQL local:

```sh
docker compose up -d postgres
```

Rode todas as migrations locais:

```sh
DATABASE_URL='postgres://b2b_local:b2b_local_password@127.0.0.1:5432/b2b_local' npm run migrate
```

Rode apenas a integração PostgreSQL:

```sh
TEST_DATABASE_URL='postgres://b2b_local:b2b_local_password@127.0.0.1:5432/b2b_local' node --test --test-concurrency=1 test/postgres.integration.test.js
```

Ou inclua-a na suíte completa:

```sh
TEST_DATABASE_URL='postgres://b2b_local:b2b_local_password@127.0.0.1:5432/b2b_local' npm test
```

O teste cria um schema com nome aleatório, aplica as migrations, exercita concorrência e remove somente esse schema no `finally`. Sem `TEST_DATABASE_URL`, ele é pulado intencionalmente.

## 13. Auto-deploy e autorizações

Um Web Service ligado a uma branch pode fazer deploy automaticamente quando essa branch recebe push. Além disso, criar Web/Worker no Dashboard dispara o primeiro build/deploy imediatamente. Por isso:

- deixe **Auto-Deploy = Off** nos dois serviços;
- não faça push da branch antes de autorização;
- não clique em Create Web Service/Create Background Worker antes de autorização para o primeiro deploy;
- alteração de env var no Render pode gerar novo deploy; trate-a como ação externa;
- registrar webhook, instalar app, criar Customer sintético e executar Admin GraphQL também são ações externas.

O trabalho local não executa nenhuma dessas ações.

## Referências oficiais

- Render Web Services: <https://render.com/docs/web-services>
- Render Background Workers: <https://render.com/docs/background-workers>
- Render Postgres: <https://render.com/docs/postgresql-creating-connecting>
- Render deploys/pre-deploy: <https://render.com/docs/deploys>
- Shopify client credentials: <https://shopify.dev/docs/apps/build/authentication-authorization/client-credentials-grant>
- Shopify protected customer data: <https://shopify.dev/docs/apps/launch/protected-customer-data>
- Shopify `webhookSubscriptionCreate`: <https://shopify.dev/docs/api/admin-graphql/latest/mutations/webhookSubscriptionCreate>
- Shopify webhook HMAC: <https://shopify.dev/docs/apps/build/webhooks/verify-deliveries>
