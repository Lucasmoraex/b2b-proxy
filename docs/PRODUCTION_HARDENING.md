# Hardening HTTP e de reservas

Esta etapa protege `POST /v1/registrations` em duas camadas. A primeira continua em memória e reduz tráfego repetitivo antes do processamento. A segunda usa PostgreSQL e é compartilhada entre todas as instâncias da aplicação.

## Modelo de dados

Migration `006_registration_abuse_controls.sql`:

- adiciona `registrations.request_ip_hash`, contendo somente HMAC SHA-256;
- cria `registration_rate_limit_buckets`, com contador atômico por janela;
- cria `registration_request_admissions`, que impede uma repetição idempotente de consumir novamente as quotas;
- cria índices de expiração e de reservas ativas por chave de rede.

O endereço IP nunca é persistido em texto puro. E-mail, CNPJ e telefone usados nos buckets também são HMACs com separação de domínio. A chave `B2B_RATE_LIMIT_KEY_SECRET` deve ter no mínimo 32 bytes e ser diferente dos secrets administrativo, webhook, registration token e índice histórico.

## Ordem do cadastro

1. Validar e normalizar o payload e a `Idempotency-Key`.
2. Retornar imediatamente uma registration idempotente já existente.
3. Registrar atomicamente a admissão e consumir os buckets compartilhados de IP e identidades.
4. Verificar a quantidade de reservas ativas e não vinculadas da chave de IP.
5. Verificar conflitos atuais e históricos.
6. Consultar cache fiscal e, somente quando necessário, o registro fiscal.
7. Reservar em transação `SERIALIZABLE`, revalidando a quota de reservas sob `pg_advisory_xact_lock`.

O mesmo payload com a mesma `Idempotency-Key` não incrementa novamente os buckets PostgreSQL. A camada em memória continua contando requisições HTTP, inclusive retries, pois sua função é contenção imediata do processo.

Respostas `429` usam somente o código público `rate_limited`; contagens, limites internos e chaves não são enviados em headers ou no corpo.

Reservas não vinculadas cujo TTL terminou deixam de consumir a quota ativa. Buckets e admissões têm `expires_at` e são removidos em lotes limitados durante novas admissões ou pelo método explícito de limpeza.

## Variáveis

| Variável | Uso | Padrão |
| --- | --- | --- |
| `B2B_RATE_LIMIT_KEY_SECRET` | HMAC exclusivo das chaves de rede/identidade | obrigatório no Web |
| `B2B_RATE_LIMIT_WINDOW_MS` | janela do limitador em memória | `60000` |
| `B2B_RATE_LIMIT_MAX` | máximo do limitador em memória | `30` |
| `B2B_SHARED_RATE_LIMIT_WINDOW_MS` | janela compartilhada por IP HMAC | `60000` |
| `B2B_SHARED_RATE_LIMIT_MAX` | tentativas compartilhadas por IP/janela | `20` |
| `B2B_IDENTITY_RATE_LIMIT_WINDOW_MS` | janela dos buckets de identidade | `900000` |
| `B2B_IDENTITY_RATE_LIMIT_MAX` | tentativas por identidade/janela | `10` |
| `B2B_ACTIVE_RESERVATIONS_PER_IP_MAX` | reservas ativas não vinculadas por IP HMAC | `5` |
| `B2B_RATE_LIMIT_STATE_RETENTION_MS` | retenção adicional do estado expirado | `86400000` |
| `B2B_RATE_LIMIT_CLEANUP_BATCH_SIZE` | máximo removido por tabela e limpeza | `200` |
| `B2B_JSON_BODY_LIMIT_BYTES` | limite dos corpos JSON comuns | `8192` |
| `B2B_WEBHOOK_BODY_LIMIT_BYTES` | limite separado do corpo bruto do webhook | `262144` |
| `B2B_TRUST_PROXY_HOPS` | quantidade exata de proxies confiáveis | obrigatório explicitamente em produção |
| `B2B_HEADER_TIMEOUT_MS` | timeout dos headers HTTP | `10000` |
| `B2B_HTTP_REQUEST_TIMEOUT_MS` | timeout total da requisição HTTP | `15000` |
| `B2B_KEEP_ALIVE_TIMEOUT_MS` | keep-alive do servidor | `5000` |

Em Render com exatamente um proxy confiável na frente do Web, configure `B2B_TRUST_PROXY_HOPS=1`. Localmente use `0`. Uma topologia diferente exige reavaliar esse número antes do rollout; confiar em proxies demais permite spoofing de `X-Forwarded-For`.

## HTTP, CORS e rotas

- Produção exige `B2B_ALLOWED_ORIGIN` com uma ou mais origens HTTP(S) exatas e exige `Origin` no cadastro.
- `localhost`, loopback e `*.shopifypreview.com` são atalhos aceitos somente fora de produção.
- CORS não autentica clientes não-browser; o rate limit e as demais validações continuam obrigatórios.
- Endpoints JSON rejeitam outro content type com `415` e payload excedente com `413`.
- Secrets/tokens encontrados em nomes de parâmetros da query string são rejeitados.
- Administração permanece apenas em `POST`, com `X-B2B-Admin-Secret` comparado em tempo constante.
- O webhook não passa pelo rate limiter de cadastro, preserva o corpo bruto e valida HMAC.
- Health checks não passam pelos limitadores.
- Legados permanecem `410`; respostas de erro públicas são genéricas.

## Limites da proteção

Rate limiting dentro da aplicação **não torna o serviço imune a DDoS**: conexões e tráfego já chegaram ao processo e possivelmente ao banco. Antes de produção, ainda é necessário controle de borda/WAF com limites por rede e reputação. Também é recomendado um desafio anti-bot cuja resposta seja validada pelo servidor antes de consumir quota, consultar o registro fiscal ou reservar identidades.

Os valores padrão são apenas ponto de partida. Métricas agregadas, sem PII, devem orientar ajustes para evitar bloqueio indevido de escritórios, NAT corporativo e redes móveis compartilhadas.
