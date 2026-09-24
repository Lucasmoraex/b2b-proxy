# Auditoria somente leitura de Customers Shopify

O comando `npm run audit:shopify-customers` pagina todos os Customers exclusivamente por queries GraphQL. Ele não importa o runtime da aplicação, não lê `DATABASE_URL`, não contém mutations e não altera Customers, metafields, tags ou qualquer outro recurso.

## Acesso mínimo

Use uma credencial dedicada à loja de desenvolvimento que tenha somente o scope Admin API:

- `read_customers`

O app também precisa ter aprovação de **Protected Customer Data** para:

- Customer;
- Email;
- Phone.

Sem essas permissões a Shopify pode ocultar os campos protegidos e a auditoria não será completa. A ferramenta recebe apenas um Admin API access token já provisionado; ela não executa OAuth nem solicita scopes.

## Variáveis

| Variável | Obrigatória | Uso |
| --- | --- | --- |
| `B2B_AUDIT_CONFIRMATION` | sim | deve ser exatamente `READ_ONLY_CUSTOMER_AUDIT` |
| `B2B_AUDIT_MODE` | sim | deve ser exatamente `read-only`; qualquer outro valor encerra a execução |
| `SHOPIFY_SHOP` | sim | domínio exato `nome-da-loja.myshopify.com` |
| `B2B_AUDIT_CONFIRMED_SHOP_DOMAIN` | sim | deve ser exatamente igual a `SHOPIFY_SHOP` |
| `SHOPIFY_ADMIN_TOKEN` | sim | token somente leitura, fornecido por mecanismo seguro e nunca colocado no comando ou no Git |
| `SHOPIFY_API_VERSION` | não | padrão `2026-07` |
| `B2B_AUDIT_TIMEOUT_MS` | não | timeout por query; padrão `8000` |
| `B2B_AUDIT_MAX_RETRIES` | não | retries para throttling/falhas transitórias; padrão `4`, máximo `10` |

`DATABASE_URL`, credenciais ReceitaWS, secrets de webhook e secrets administrativos não são lidos.

## Execução futura

Depois de disponibilizar `SHOPIFY_ADMIN_TOKEN` no ambiente seguro do terminal, sem colocá-lo no histórico:

```bash
B2B_AUDIT_CONFIRMATION=READ_ONLY_CUSTOMER_AUDIT \
B2B_AUDIT_MODE=read-only \
SHOPIFY_SHOP=development-store.myshopify.com \
B2B_AUDIT_CONFIRMED_SHOP_DOMAIN=development-store.myshopify.com \
SHOPIFY_API_VERSION=2026-07 \
npm run audit:shopify-customers
```

O domínio deve ser substituído pelo domínio exato da development store autorizada. Não execute o comando contra produção sem uma autorização separada e explícita.

## Dados consultados

Cada página solicita somente:

- Customer ID;
- email;
- telefone oficial;
- tags;
- `custom.cnpj`;
- `custom.cjnpj`;
- `custom.cnpj_status`;
- `note`, usada em memória apenas quando contém `CNPJ: ... | CEL: ...`.

A normalização de email, CNPJ e telefone é a mesma usada por `/v1/registrations`.

## Saída e relatório

O stdout contém somente totais agregados da auditoria e da revisão de duplicidades. Retries sanitizados são enviados ao stderr sem domínio, token ou dados de Customer.

O relatório completo é criado em:

```text
.shopify-audit-reports/duplicate-review-<data>-<uuid>.json
```

O diretório está ignorado pelo Git, recebe permissão `700` e cada arquivo recebe permissão `600`. O relatório contém:

- versão e instante da auditoria;
- hash não reversível e específico da execução para o domínio;
- totais e contagens por categoria;
- Customer IDs afetados;
- hashes específicos da execução para valores duplicados;
- presença e validade do email, nunca seu valor;
- fingerprints HMAC de CNPJ e telefones normalizados, sem persistir os valores ou a chave HMAC;
- fonte e validade dos identificadores;
- estado normalizado de `custom.cnpj_status` e flags booleanas das tags B2B;
- grupos de CNPJ e telefone, componentes conectados, sobreposição e quantidade teórica de merges;
- nomes das fontes divergentes, nunca seus valores.

Email, CNPJ, telefone, note, token, secrets e domínio da loja não são persistidos no relatório.

A query é comparada literalmente com a allowlist `CUSTOMER_AUDIT_QUERY`. Qualquer outra query, mutation ou subscription encerra a execução antes da chamada HTTP.

Categorias verificadas:

- duplicidade de email, CNPJ e telefone;
- email, CNPJ e telefone inválidos;
- ausência de `custom.cnpj` ou `custom.cnpj_status`;
- inconsistências entre `b2b-approved`, `b2b-pending` e status;
- `b2b-approved` sem `custom.cnpj` válido;
- divergência entre `custom.cnpj`, `custom.cjnpj` e note;
- divergência entre telefone oficial e telefone do note.

## Remoção segura do relatório local

Primeiro liste apenas os relatórios no diretório dedicado:

```bash
find .shopify-audit-reports -maxdepth 1 -type f -name 'duplicate-review-*.json' -print
```

Depois remova interativamente somente os arquivos conferidos:

```bash
find .shopify-audit-reports -maxdepth 1 -type f -name 'duplicate-review-*.json' -exec rm -i -- {} \;
rmdir .shopify-audit-reports 2>/dev/null || true
```

Em SSDs e filesystems com snapshots, a exclusão lógica não garante sobrescrita física imediata. Evite backups ou sincronização desse diretório.
