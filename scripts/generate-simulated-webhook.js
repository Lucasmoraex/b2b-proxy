import crypto from "node:crypto";
import { loadConfig } from "../src/config.js";
import { assertSimulationSafety } from "../src/simulation.js";

const config = loadConfig();
if (!config.simulationMode) throw new Error("This fixture generator is restricted to simulation mode");
assertSimulationSafety(config, { role: "web" });

const target = process.argv[2] || "https://b2b-v2-staging.example.invalid/webhooks/shopify/customers-create";
let targetUrl;
try { targetUrl = new URL(target); } catch { throw new Error("The target must be a valid URL"); }
if (targetUrl.pathname !== "/webhooks/shopify/customers-create") throw new Error("Unexpected webhook path");
const allowedHost = targetUrl.hostname.endsWith(".invalid")
  || ["localhost", "127.0.0.1"].includes(targetUrl.hostname)
  || targetUrl.hostname.toLowerCase().includes("staging");
if (!allowedHost) throw new Error("The target host must be local, .invalid, or explicitly contain staging");

const rawBody = JSON.stringify({ id: "synthetic-customer-staging", email: "b2b-staging@example.invalid" });
const hmac = crypto.createHmac("sha256", config.shopifyWebhookSecret).update(rawBody).digest("base64");
const webhookId = crypto.randomUUID();
const continuation = "\\";

process.stdout.write([
  "Synthetic simulation-only request (the secret is not printed):",
  `curl --request POST '${targetUrl.toString()}' ${continuation}`,
  `  --header 'Content-Type: application/json' ${continuation}`,
  `  --header 'X-Shopify-Hmac-Sha256: ${hmac}' ${continuation}`,
  `  --header 'X-Shopify-Webhook-Id: ${webhookId}' ${continuation}`,
  `  --header 'X-Shopify-Topic: customers/create' ${continuation}`,
  `  --header 'X-Shopify-Shop-Domain: simulation.example.invalid' ${continuation}`,
  `  --data-binary '${rawBody}'`,
  "",
].join("\n"));
