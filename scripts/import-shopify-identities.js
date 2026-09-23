import fetch from "node-fetch";
import pg from "pg";
import { runHistoricalIdentityImportCommand } from "../src/identity/import-command.js";
import { createLogger } from "../src/logger.js";

const safeLogger = createLogger({
  log: () => {},
  warn: (line) => process.stderr.write(`${line}\n`),
  error: (line) => process.stderr.write(`${line}\n`),
});

try {
  await runHistoricalIdentityImportCommand({
    env: process.env,
    fetchImpl: fetch,
    PoolClass: pg.Pool,
    logger: safeLogger,
    stdout: process.stdout,
  });
} catch (error) {
  const known = new Set([
    "identity_import_mode_invalid", "identity_import_shop_confirmation_mismatch",
    "identity_import_shop_invalid", "identity_import_shopify_token_required",
    "identity_index_secret_invalid", "identity_index_secret_reuse_forbidden", "identity_import_disabled",
    "identity_import_confirmation_required", "identity_import_production_refused",
    "identity_import_database_required", "identity_import_api_version_invalid",
    "invalid_identity_import_configuration", "shopify_audit_unavailable",
    "shopify_audit_query_failed", "shopify_audit_pagination_failed",
    "historical_identity_index_unavailable", "historical_identity_registration_conflict",
    "historical_identity_post_import_verification_failed",
  ]);
  const candidate = error?.code || error?.message;
  if (error?.importPromoted) {
    safeLogger.error("historical_identity_post_import_verification_failed", {
      code: "historical_identity_post_import_verification_failed",
      importStatus: "already_promoted",
      action: "do_not_repeat_import",
    });
  } else {
    safeLogger.error("historical_identity_import_command_failed", {
      code: known.has(candidate) ? candidate : "internal_error",
    });
  }
  process.exitCode = 1;
}
