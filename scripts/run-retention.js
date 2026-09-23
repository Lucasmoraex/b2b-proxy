import pg from "pg";
import { createLogger } from "../src/logger.js";
import { loadRetentionConfig } from "../src/retention-config.js";
import { RetentionService } from "../src/retention.js";
import { PostgresRegistrationStore } from "../src/storage/postgres-store.js";

const logger = createLogger({
  log: (line) => process.stderr.write(`${line}\n`),
  warn: (line) => process.stderr.write(`${line}\n`),
  error: (line) => process.stderr.write(`${line}\n`),
});

let pool;
try {
  const config = loadRetentionConfig(process.env);
  pool = new pg.Pool({
    connectionString: config.databaseUrl,
    ssl: config.databaseSsl ? { rejectUnauthorized: true } : false,
  });
  const service = new RetentionService({ store: new PostgresRegistrationStore({ pool }), logger });
  const summary = await service.run(config);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
} catch {
  logger.error("retention_command_failed", { code: "operation_failed", category: "internal" });
  process.exitCode = 1;
} finally {
  if (pool) await pool.end();
}
