import fetch from "node-fetch";
import { ShopifyGraphqlClient } from "../src/clients/shopify-graphql.js";
import { loadConfig } from "../src/config.js";

const config = loadConfig();
const callback = process.env.SHOPIFY_WEBHOOK_CALLBACK_URL || "";
const confirmedShop = process.env.B2B_CONFIRMED_DEVELOPMENT_STORE_DOMAIN || "";
const confirmation = process.env.B2B_SHOPIFY_SETUP_CONFIRMATION || "";

if (config.environment !== "staging" || config.simulationMode) throw new Error("Webhook registration is restricted to non-simulated staging");
if (confirmation !== "REGISTER_DEVELOPMENT_STORE_WEBHOOK") throw new Error("Explicit staging webhook confirmation is missing");
if (confirmedShop !== config.shop) throw new Error("Confirmed development store must exactly match SHOPIFY_SHOP");
if (!config.shop || (!config.shopifyToken && !(config.shopifyClientId && config.shopifyClientSecret))) throw new Error("Shopify staging authentication is incomplete");

let callbackUrl;
try { callbackUrl = new URL(callback); } catch { throw new Error("SHOPIFY_WEBHOOK_CALLBACK_URL must be a valid URL"); }
if (callbackUrl.protocol !== "https:" || callbackUrl.pathname !== "/webhooks/shopify/customers-create") {
  throw new Error("Webhook callback must use HTTPS and the customers-create path");
}
if (!callbackUrl.hostname.toLowerCase().includes("staging")) throw new Error("Webhook callback hostname must contain staging");

const client = new ShopifyGraphqlClient({
  fetchImpl: fetch,
  shop: config.shop,
  token: config.shopifyToken,
  clientId: config.shopifyClientId,
  clientSecret: config.shopifyClientSecret,
  apiVersion: config.shopifyApiVersion,
  timeoutMs: config.requestTimeoutMs,
});

const subscription = await client.createCustomersCreateWebhook(callbackUrl.toString());
process.stdout.write(`Created webhook subscription ${subscription.id} for ${subscription.topic}\n`);
