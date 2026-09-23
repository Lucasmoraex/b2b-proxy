import fetch from "node-fetch";
import pg from "pg";
import { createApp } from "./app.js";
import { ShopifyGraphqlClient } from "./clients/shopify-graphql.js";
import { assertReceitaWsAuthConfig, ReceitaWsClient } from "./clients/receita-ws.js";
import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { assertSimulationSafety, SimulatedRegistryClient, SimulatedShopifyClient } from "./simulation.js";
import { PostgresRegistrationStore } from "./storage/postgres-store.js";
import { OutboxWorker } from "./worker.js";
import { assertDedicatedIdentityIndexSecret, isHistoricalIdentityShopDomain } from "./identity/historical-identities.js";
import { assertWebHttpSecurityConfig } from "./http-security.js";
import { assertDedicatedRateLimitKeySecret } from "./rate-limit.js";
import { assertDedicatedDataDigestSecret, DATA_DIGEST_VERSION } from "./data-digests.js";
import { createPiiEncryptionKeyring } from "./pii-crypto.js";

const common = ({ config, clock, sink }) => {
  if (!config.databaseUrl) throw new Error("Missing required environment configuration: DATABASE_URL");
  const logger = createLogger(sink);
  const pool = new pg.Pool({ connectionString: config.databaseUrl, ssl: config.databaseSsl ? { rejectUnauthorized: true } : false });
  const store = new PostgresRegistrationStore({ pool, clock });
  return { config, logger, store };
};

export function buildWebRuntime({ env = process.env, fetchImpl = fetch, clock = () => new Date(), sink = console } = {}) {
  const config = loadConfig(env);
  assertSimulationSafety(config, { role: "web" });
  assertWebHttpSecurityConfig(config);
  assertReceitaWsAuthConfig({ token: config.registryToken, tokenMode: config.registryTokenMode });
  const missing = [];
  if (!config.shopifyWebhookSecret) missing.push("SHOPIFY_WEBHOOK_SECRET");
  if (!config.adminSecret) missing.push("B2B_ADMIN_SECRET");
  if (!config.registrationTokenSecret) missing.push("B2B_REGISTRATION_TOKEN_SECRET");
  if (!config.dataDigestSecret) missing.push("B2B_DATA_DIGEST_SECRET");
  if (!config.piiEncryptionActiveKeyVersion) missing.push("B2B_PII_ENCRYPTION_ACTIVE_KEY_VERSION");
  if (!config.piiEncryptionKeys) missing.push("B2B_PII_ENCRYPTION_KEYS");
  if (!config.rateLimitKeySecret) missing.push("B2B_RATE_LIMIT_KEY_SECRET");
  if (missing.length) throw new Error(`Missing required environment configuration: ${missing.join(", ")}`);
  if (config.dataDigestVersion !== DATA_DIGEST_VERSION) throw new Error("data_digest_version_invalid");
  assertDedicatedDataDigestSecret(config.dataDigestSecret, [
    config.adminSecret,
    config.registrationTokenSecret,
    config.shopifyWebhookSecret,
    config.identityIndexSecret,
    config.rateLimitKeySecret,
    config.registryToken,
    config.shopifyToken,
    config.shopifyClientSecret,
  ]);
  assertDedicatedRateLimitKeySecret(config.rateLimitKeySecret, [
    config.adminSecret,
    config.registrationTokenSecret,
    config.shopifyWebhookSecret,
    config.identityIndexSecret,
    config.dataDigestSecret,
  ]);
  const piiKeyring = createPiiEncryptionKeyring({
    activeVersion: config.piiEncryptionActiveKeyVersion,
    serializedKeys: config.piiEncryptionKeys,
    otherSecrets: [
      config.adminSecret, config.registrationTokenSecret, config.shopifyWebhookSecret,
      config.identityIndexSecret, config.dataDigestSecret, config.rateLimitKeySecret,
      config.registryToken, config.shopifyToken, config.shopifyClientSecret,
    ],
  });
  if (config.enableHistoricalIdentityLookup) {
    if (!isHistoricalIdentityShopDomain(config.shop, { allowSynthetic: config.simulationMode })) {
      throw new Error("Missing required environment configuration: SHOPIFY_SHOP");
    }
    assertDedicatedIdentityIndexSecret(config.identityIndexSecret, [
      config.adminSecret,
      config.registrationTokenSecret,
      config.shopifyWebhookSecret,
      config.dataDigestSecret,
      config.rateLimitKeySecret,
    ]);
  }

  const runtime = common({ config, clock, sink });
  const { logger, store } = runtime;

  const registryClient = config.simulationMode
    ? new SimulatedRegistryClient({ scenario: config.simulatedRegistryScenario })
    : new ReceitaWsClient({ fetchImpl, baseUrl: config.registryBaseUrl, token: config.registryToken, tokenMode: config.registryTokenMode, timeoutMs: config.requestTimeoutMs });
  const simulationController = config.simulationMode ? {
    getRegistryScenario: () => registryClient.getScenario(),
    setRegistryScenario: (scenario) => registryClient.setScenario(scenario),
  } : null;
  const app = createApp({ config, store, registryClient, logger, clock, simulationController, piiKeyring });
  return { app, store, config, logger, close: () => store.close() };
}

export function buildWorkerRuntime({ env = process.env, fetchImpl = fetch, clock = () => new Date(), sink = console } = {}) {
  const config = loadConfig(env);
  assertSimulationSafety(config, { role: "worker" });
  if (!config.simulationMode && (!config.shop || (!config.shopifyToken && !(config.shopifyClientId && config.shopifyClientSecret)))) {
    throw new Error("Missing required environment configuration: SHOPIFY_SHOP and Shopify authentication");
  }
  const piiKeyring = createPiiEncryptionKeyring({
    activeVersion: config.piiEncryptionActiveKeyVersion,
    serializedKeys: config.piiEncryptionKeys,
    otherSecrets: [
      config.adminSecret, config.registrationTokenSecret, config.shopifyWebhookSecret,
      config.identityIndexSecret, config.dataDigestSecret, config.rateLimitKeySecret,
      config.registryToken, config.shopifyToken, config.shopifyClientSecret,
    ],
  });
  const runtime = common({ config, clock, sink });
  const { logger, store } = runtime;
  const shopifyClient = config.simulationMode
    ? new SimulatedShopifyClient({ store })
    : new ShopifyGraphqlClient({
      fetchImpl, shop: config.shop, token: config.shopifyToken,
      clientId: config.shopifyClientId, clientSecret: config.shopifyClientSecret,
      apiVersion: config.shopifyApiVersion, timeoutMs: config.requestTimeoutMs, clock,
    });
  const worker = new OutboxWorker({
    store, shopifyClient, clock, logger, piiKeyring,
    syncedPayloadRetentionMs: config.retentionSyncedPayloadMs,
    autoApprove: config.autoApprove, maxAttempts: config.workerMaxAttempts,
  });
  return { worker, store, config, logger, close: () => store.close() };
}
