import fetch from "node-fetch";
import pg from "pg";
import { createApp } from "./app.js";
import { ShopifyGraphqlClient } from "./clients/shopify-graphql.js";
import { ReceitaWsClient } from "./clients/receita-ws.js";
import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { assertSimulationSafety, SimulatedRegistryClient, SimulatedShopifyClient } from "./simulation.js";
import { PostgresRegistrationStore } from "./storage/postgres-store.js";
import { OutboxWorker } from "./worker.js";

const common = ({ env, clock, sink }) => {
  const config = loadConfig(env);
  if (!config.databaseUrl) throw new Error("Missing required environment configuration: DATABASE_URL");
  const logger = createLogger(sink);
  const pool = new pg.Pool({ connectionString: config.databaseUrl, ssl: config.databaseSsl ? { rejectUnauthorized: true } : false });
  const store = new PostgresRegistrationStore({ pool, clock });
  return { config, logger, store };
};

export function buildWebRuntime({ env = process.env, fetchImpl = fetch, clock = () => new Date(), sink = console } = {}) {
  const runtime = common({ env, clock, sink });
  const { config, logger, store } = runtime;
  assertSimulationSafety(config, { role: "web" });
  const missing = [];
  if (!config.shopifyWebhookSecret) missing.push("SHOPIFY_WEBHOOK_SECRET");
  if (!config.adminSecret) missing.push("B2B_ADMIN_SECRET");
  if (!config.registrationTokenSecret) missing.push("B2B_REGISTRATION_TOKEN_SECRET");
  if (missing.length) throw new Error(`Missing required environment configuration: ${missing.join(", ")}`);

  const registryClient = config.simulationMode
    ? new SimulatedRegistryClient({ scenario: config.simulatedRegistryScenario })
    : new ReceitaWsClient({ fetchImpl, baseUrl: config.registryBaseUrl, token: config.registryToken, tokenMode: config.registryTokenMode, timeoutMs: config.requestTimeoutMs });
  const simulationController = config.simulationMode ? {
    getRegistryScenario: () => registryClient.getScenario(),
    setRegistryScenario: (scenario) => registryClient.setScenario(scenario),
  } : null;
  const app = createApp({ config, store, registryClient, logger, clock, simulationController });
  return { app, store, config, logger, close: () => store.close() };
}

export function buildWorkerRuntime({ env = process.env, fetchImpl = fetch, clock = () => new Date(), sink = console } = {}) {
  const runtime = common({ env, clock, sink });
  const { config, logger, store } = runtime;
  assertSimulationSafety(config, { role: "worker" });
  if (!config.simulationMode && (!config.shop || (!config.shopifyToken && !(config.shopifyClientId && config.shopifyClientSecret)))) {
    throw new Error("Missing required environment configuration: SHOPIFY_SHOP and Shopify authentication");
  }
  const shopifyClient = config.simulationMode
    ? new SimulatedShopifyClient({ store })
    : new ShopifyGraphqlClient({
      fetchImpl, shop: config.shop, token: config.shopifyToken,
      clientId: config.shopifyClientId, clientSecret: config.shopifyClientSecret,
      apiVersion: config.shopifyApiVersion, timeoutMs: config.requestTimeoutMs, clock,
    });
  const worker = new OutboxWorker({ store, shopifyClient, clock, logger, autoApprove: config.autoApprove, maxAttempts: config.workerMaxAttempts });
  return { worker, store, config, logger, close: () => store.close() };
}
