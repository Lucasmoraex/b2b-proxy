import fetch from "node-fetch";
import pg from "pg";
import { createApp } from "./app.js";
import { ShopifyGraphqlClient } from "./clients/shopify-graphql.js";
import { ReceitaWsClient } from "./clients/receita-ws.js";
import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { PostgresRegistrationStore } from "./storage/postgres-store.js";
import { OutboxWorker } from "./worker.js";

const required = (config) => {
  const missing = [];
  if (!config.databaseUrl) missing.push("DATABASE_URL");
  if (!config.shop || !config.shopifyToken) missing.push("SHOPIFY_SHOP/SHOPIFY_ADMIN_TOKEN");
  if (!config.shopifyWebhookSecret) missing.push("SHOPIFY_WEBHOOK_SECRET");
  if (!config.adminSecret) missing.push("B2B_ADMIN_SECRET");
  if (!config.registrationTokenSecret) missing.push("B2B_REGISTRATION_TOKEN_SECRET");
  if (missing.length) throw new Error(`Missing required environment configuration: ${missing.join(", ")}`);
};

export function buildRuntime({ env = process.env, fetchImpl = fetch, clock = () => new Date(), sink = console } = {}) {
  const config = loadConfig(env);
  required(config);
  const logger = createLogger(sink);
  const pool = new pg.Pool({ connectionString: config.databaseUrl, ssl: config.databaseSsl ? { rejectUnauthorized: true } : false });
  const store = new PostgresRegistrationStore({ pool, clock });
  const registryClient = new ReceitaWsClient({
    fetchImpl, baseUrl: config.registryBaseUrl, token: config.registryToken,
    tokenMode: config.registryTokenMode, timeoutMs: config.requestTimeoutMs,
  });
  const shopifyClient = new ShopifyGraphqlClient({
    fetchImpl, shop: config.shop, token: config.shopifyToken,
    apiVersion: config.shopifyApiVersion, timeoutMs: config.requestTimeoutMs,
  });
  const app = createApp({ config, store, registryClient, logger, clock });
  const worker = new OutboxWorker({ store, shopifyClient, clock, logger, autoApprove: config.autoApprove, maxAttempts: config.workerMaxAttempts });
  return { app, worker, store, config, logger, close: () => store.close() };
}
