# Índice de identidades históricas

O índice impede que um novo cadastro reutilize e-mail, CNPJ ou telefone já observado em Customers existentes. Ele não altera Customers, não importa senhas e não armazena os identificadores históricos em texto puro.

## Modelo de dados

- `historical_identity_index_metadata`: fixa por loja o fingerprint da chave HMAC e aponta para um único `active_import_run_id`. Uma chave ausente/diferente ou a ausência de snapshot ativo concluído faz o lookup falhar fechado com indisponibilidade.
- `historical_identity_import_runs`: registra `staging`, conclusão, falha e totais agregados de cada execução de escrita. O valor legado `running` permanece aceito apenas para preservar runs criados antes da migration 005.
- `historical_customer_identity_snapshot_states`: registra, por run, Customer e tipo, `valid`, `invalid` ou `incomplete`, além das fontes verificadas. Não contém o valor original.
- `historical_identity_snapshot_members`: contém, por run, apenas HMAC SHA-256, Customer ID, tipo, fontes e timestamp.
- `historical_identity_claims`: view que considera exclusivamente o `active_import_run_id` cujo run está `completed`, derivando `active` para um único Customer e `conflicted` para mais de um Customer com o mesmo hash.
- `historical_customer_identity_states` e `historical_identity_members`: tabelas legadas da migration 004, preservadas para diagnóstico de imports anteriores; não participam mais do lookup.

A chave primária de membros é `(import_run_id, shop_domain, shopify_customer_id, identity_type, value_hash)`. O índice de busca em `(shop_domain, import_run_id, identity_type, value_hash)` é propositalmente não único, pois duplicidades históricas precisam continuar representáveis.

Claims válidos, sejam `active` ou `conflicted`, bloqueiam novos cadastros. Estados `invalid` e `incomplete` não geram claim utilizável. Um conflito retorna apenas `email_in_use`, `cnpj_in_use` ou `phone_in_use`; a API não informa quantos Customers compartilham o identificador.

## Variáveis

Aplicação Web:

- `B2B_ENABLE_HISTORICAL_IDENTITY_LOOKUP=false` — desligada por padrão;
- `B2B_IDENTITY_INDEX_SECRET` — chave exclusiva com no mínimo 32 bytes;
- `SHOPIFY_SHOP` — loja à qual o índice pertence.

Importador:

- `B2B_IDENTITY_IMPORT_MODE=dry-run` ou `write`;
- `B2B_ENABLE_HISTORICAL_IDENTITY_IMPORT=false`;
- `B2B_IDENTITY_IMPORT_CONFIRMATION=IMPORT_HISTORICAL_IDENTITIES` somente para escrita;
- `B2B_IDENTITY_IMPORT_CONFIRMED_SHOP_DOMAIN` exatamente igual a `SHOPIFY_SHOP`;
- `B2B_ALLOW_PRODUCTION_IDENTITY_IMPORT=false`;
- `B2B_IDENTITY_IMPORT_TIMEOUT_MS`;
- `B2B_IDENTITY_IMPORT_MAX_RETRIES`;
- `SHOPIFY_ADMIN_TOKEN`, fornecido apenas por mecanismo seguro no ambiente;
- `SHOPIFY_API_VERSION`;
- `DATABASE_URL` e `DATABASE_SSL` somente no modo `write`.

`B2B_IDENTITY_INDEX_SECRET` não pode reutilizar o secret administrativo, de webhook ou de registration token. O banco guarda somente um fingerprint para detectar troca da chave. A chave em si nunca é persistida.

## Segurança do importador

`npm run import:shopify-identities` usa o mesmo cliente GraphQL somente leitura da auditoria. A única operação permitida é a query literal `CUSTOMER_AUDIT_QUERY`; qualquer outra query, mutation ou subscription é recusada antes do HTTP.

O modo `dry-run` não abre `DATABASE_URL` e não escreve no banco. O modo `write` exige simultaneamente a flag, a confirmação textual e o domínio confirmado. Em `B2B_ENVIRONMENT=production`, também exige a autorização operacional adicional `B2B_ALLOW_PRODUCTION_IDENTITY_IMPORT=true`; o padrão é recusar.

Stdout contém apenas contagens agregadas. E-mail, CNPJ, telefone, note, tokens e secrets não são logados. A normalização ocorre em memória, e apenas HMACs completos são enviados ao armazenamento.

## Staging, promoção e concorrência

Cada importação grava apenas linhas associadas ao próprio run em estado `staging`. Falhar durante qualquer página marca o run como `failed`, preserva as linhas para diagnóstico e não altera `active_import_run_id`. Em refreshes, o snapshot anterior continua servindo o lookup até a promoção do novo.

Cadastro e importação de páginas usam o mesmo helper de advisory locks transacionais (`pg_advisory_xact_lock`) por loja/tipo/hash, sempre em ordem lexicográfica `cnpj`, `email`, `phone`. Esses locks são liberados automaticamente no fim da transação. O cadastro também mantém um lock global compartilhado de cutover durante a reserva; a promoção usa o mesmo lock global em modo exclusivo.

A promoção roda numa única transação `SERIALIZABLE`: bloqueia o cutover, trava metadata/run, incorpora ao novo snapshot as identidades do snapshot anterior que não devem ser apagadas automaticamente, revalida globalmente todas as registrations ativas, marca o run como `completed` e só então troca `active_import_run_id`. Qualquer conflito ou erro reverte a transação inteira. Isso também detecta uma registration criada depois do processamento de uma página.

## Rollout futuro — não executado

1. Aplicar `004_historical_identity_index.sql` e `005_atomic_historical_identity_snapshots.sql` no PostgreSQL de staging.
2. Configurar uma chave exclusiva e estável em secret storage, mantendo lookup e importação de escrita desligados.
3. Executar `dry-run` read-only com uma credencial que tenha apenas `read_customers` e conferir totais agregados.
4. Ativar temporariamente apenas a flag de importação em staging, usar confirmação textual e importar no PostgreSQL de staging.
5. Conferir estados, contagens de claims `active`/`conflicted`, idempotência e bloqueios por tipo.
6. Repetir a importação com o mesmo secret e validar que somente o snapshot promovido participa do lookup.
7. Imediatamente antes do cutover, obter um snapshot read-only recente, pois a base de Customers permanece ativa.
8. Executar a importação final, desativar novamente a flag do importador e só então habilitar `B2B_ENABLE_HISTORICAL_IDENTITY_LOOKUP=true` no Web.
9. Monitorar somente códigos e contagens agregadas, sem PII.

Rollback: definir `B2B_ENABLE_HISTORICAL_IDENTITY_LOOKUP=false` e reiniciar o Web. Os dados do índice permanecem intactos para auditoria ou nova ativação; nenhuma linha deve ser apagada como parte do rollback.

O importador nunca remove automaticamente claims que deixem de aparecer numa execução posterior. Qualquer política de expiração ou remoção exige projeto, revisão e autorização separados.

## Verificação pós-importação DB-only

Importação e verificação são operações distintas:

- `npm run import:shopify-identities` executa a única leitura Shopify autorizada, grava o snapshot e o promove;
- `npm run verify:historical-identities` consulta somente o PostgreSQL local já promovido, em transação `REPEATABLE READ READ ONLY`.

O verificador não lê nem exige `SHOPIFY_ADMIN_TOKEN`, não instancia cliente Shopify e não executa importação. Ele retorna somente totais agregados de runs, snapshot ativo, states, members e claims.

Configuração do verificador local:

- `DATABASE_URL` apontando para `localhost` ou `127.0.0.1`;
- `DATABASE_SSL=false`;
- `B2B_IDENTITY_VERIFICATION_CONFIRMED_DATABASE` exatamente igual ao banco da URL;
- `B2B_IDENTITY_VERIFICATION_SHOP_DOMAIN` com o domínio exato da loja representada no snapshot.

Se a verificação automática posterior falhar depois da promoção, o importador emite `historical_identity_post_import_verification_failed` com `importStatus=already_promoted` e `action=do_not_repeat_import`. Nesse caso, a importação não deve ser repetida: execute apenas `npm run verify:historical-identities`.
