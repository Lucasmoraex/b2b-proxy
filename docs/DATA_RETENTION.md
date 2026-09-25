# Minimização e retenção do cadastro

## Modelo persistido

`registration_identity_claims` contém somente `registration_id`, tipo, versão da chave, HMAC SHA-256 e estado. O domínio do HMAC é separado por tipo (`email`, `cnpj`, `phone`). O índice parcial único cobre todos os claims que não estão `released` e é a garantia atômica final contra concorrência. Não há valor normalizado nessa tabela.

`registration_operational_payloads` contém o payload mínimo necessário ao webhook/worker cifrado com AES-256-GCM, incluindo `employee_range` para novos cadastros. O AAD liga o ciphertext ao `registration_id` e à finalidade `registration-operational-payload:v1`. Nonce de 12 bytes e auth tag de 16 bytes são persistidos separadamente. As colunas legadas `email_normalized`, `cnpj_normalized` e `phone_e164` de `registrations` ficaram nullable; novas reservations gravam `NULL` nelas. `employee_range_required` diferencia novos registros de filas legadas sem armazenar a faixa em texto puro. A leitura legada existe apenas para registros anteriores à migration.

O webhook calcula o blind index do e-mail e associa a reservation por esse índice. Depois da associação, todas as operações usam `shopify_customer_id`. O worker descriptografa CNPJ e telefone somente enquanto o payload ainda é operacionalmente necessário.

O cache fiscal continua contendo CNPJ normalizado durante seu TTL operacional para evitar consultas repetidas. Ele não substitui os blind indexes e é apagável quando expira. Isso deve ser considerado ao definir o prazo final de retenção.

## Máquina de estados dos claims

- `reserved`: reservation criada, ainda sem Customer.
- `active`: Customer associado; e-mail e telefone permanecem bloqueantes enquanto a conta existir.
- `tombstoned`: CNPJ sincronizado e permanentemente bloqueante sem conservar o valor legível.
- `released`: somente reservation sem Customer que venceu o prazo aplicável; deixa de bloquear, mas preserva evidência mínima do ciclo de vida.

Claims `active` e `tombstoned` nunca são liberados pela retenção. Registrations vinculadas continuam bloqueantes mesmo em `failed` ou `rejected`. A liberação futura de CNPJ tombstoned exige uma operação administrativa explícita que não existe nesta versão.

## Chaves de criptografia

- `B2B_PII_ENCRYPTION_ACTIVE_KEY_VERSION`: versão usada em novas escritas.
- `B2B_PII_ENCRYPTION_KEYS`: JSON `versão -> chave base64` com chaves de exatamente 32 bytes.

Todas as versões ainda necessárias para leitura devem permanecer no keyring durante uma rotação. A versão ativa precisa existir, versões/chaves duplicadas são recusadas e a chave não pode reutilizar secrets do webhook, admin, token de registration, digests, rate limit, índice histórico ou credenciais externas. Chaves nunca devem ser registradas.

## Retenção

Padrões seguros:

| Variável | Padrão | Finalidade |
| --- | ---: | --- |
| `B2B_RETENTION_ENABLED` | `false` | trava geral de escrita |
| `B2B_RETENTION_MODE` | `report-only` | relatório sem mutação |
| `B2B_RETENTION_EXPIRED_UNLINKED_MS` | `86400000` | espera depois da expiração de reservation sem Customer |
| `B2B_RETENTION_SYNCED_PAYLOAD_MS` | `604800000` | retenção do payload depois da sincronização |
| `B2B_RETENTION_FAILED_UNLINKED_MS` | `2592000000` | espera de `failed`/`rejected` sem Customer |
| `B2B_RETENTION_OPERATIONAL_EVENTS_MS` | `2592000000` | outbox processada, webhook events e runs inativos |
| `B2B_RETENTION_BATCH_SIZE` | `200` | limite por lote |

`npm run retention` usa `report-only` por padrão. O relatório lê apenas contagens agregadas. Uma execução mutável exige simultaneamente modo `execute`, feature habilitada e confirmação exata `EXECUTE_B2B_RETENTION`. Produção continua recusada sem uma liberação adicional explícita. Não habilitar essas travas antes da decisão jurídico/negócio sobre os prazos.

Em modo de execução, os lotes usam `FOR UPDATE SKIP LOCKED`. `retention_hold_until` impede purge/release da registration. Payload com outbox pendente não é purgado. A limpeza técnica é limitada a:

- payload já sincronizado e vencido;
- reservation expirada sem Customer, ou `failed`/`rejected` sem Customer depois do prazo específico;
- outbox já processada e webhook events antigos;
- cache fiscal, buckets e admissions expirados;
- runs históricos falhos/substituídos, nunca o snapshot ativo.

O comando escreve apenas totais agregados nos logs/stdout. A implementação não executa em loop: cada chamada processa no máximo um lote.

## Reconciliação após purge

Sem payload, uma reconciliação que precisaria de CNPJ/telefone falha com o código estruturado `payload_purged`; ela não agenda retry e nunca libera o tombstone de CNPJ. Uma projeção futura poderá validar o estado lendo Shopify por `customer_id`, mas isso não foi implementado nesta etapa.

## Fora de escopo

Esta fase não altera Customers Shopify, não registra webhooks de privacidade e não escolhe prazos legais definitivos. Também não implementa liberação administrativa de tombstones nem remoção de claims por exclusão de Customer.
