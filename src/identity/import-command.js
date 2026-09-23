import { ReadOnlyShopifyCustomerClient } from "../audit/shopify-customer-client.js";
import { createReadOnlyTelemetry } from "../audit/read-only-telemetry.js";
import { HistoricalIdentityImporter } from "../services/historical-identity-importer.js";
import { PostgresRegistrationStore } from "../storage/postgres-store.js";
import { loadHistoricalIdentityImportConfig } from "./import-config.js";
import {
  runImportWithPostVerification,
  verifyActiveHistoricalIdentitySnapshot,
} from "./snapshot-verifier.js";

export async function runHistoricalIdentityImportCommand({
  env,
  fetchImpl,
  PoolClass,
  logger,
  stdout,
  clock,
  durationClock,
}) {
  const config = loadHistoricalIdentityImportConfig(env);
  const telemetry = createReadOnlyTelemetry();
  const client = new ReadOnlyShopifyCustomerClient({
    fetchImpl,
    shopDomain: config.shopDomain,
    token: config.token,
    apiVersion: config.apiVersion,
    timeoutMs: config.timeoutMs,
    maxRetries: config.maxRetries,
    logger,
    telemetry,
  });
  let pool;
  try {
    let store;
    if (!config.dryRun) {
      pool = new PoolClass({
        connectionString: config.databaseUrl,
        ssl: config.databaseSsl ? { rejectUnauthorized: true } : false,
      });
      store = new PostgresRegistrationStore({ pool, clock });
    }
    const importer = new HistoricalIdentityImporter({
      store,
      shopDomain: config.shopDomain,
      identityIndexSecret: config.identityIndexSecret,
      registrationIdentitySecret: config.registrationIdentitySecret,
      logger,
      telemetry,
      clock,
      durationClock,
    });
    const executeImport = () => importer.run({
      pages: client.customerPages(), dryRun: config.dryRun, confirmation: config.confirmation,
    });
    const result = config.dryRun
      ? await executeImport()
      : await runImportWithPostVerification({
        executeImport,
        verifySnapshot: () => verifyActiveHistoricalIdentitySnapshot({
          pool,
          shopDomain: config.shopDomain,
        }),
      });
    stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result;
  } finally {
    await pool?.end();
  }
}
