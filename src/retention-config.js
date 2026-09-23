import { loadConfig } from "./config.js";
import { RETENTION_EXECUTION_CONFIRMATION } from "./retention.js";

const bool = (value, fallback = false) => value === undefined || value === ""
  ? fallback
  : String(value).toLowerCase() === "true";

export function loadRetentionConfig(env = process.env) {
  const base = loadConfig(env);
  if (!["report-only", "execute"].includes(base.retentionMode)) throw new Error("retention_mode_invalid");
  if (!base.databaseUrl) throw new Error("retention_database_required");
  const config = {
    databaseUrl: base.databaseUrl,
    databaseSsl: base.databaseSsl,
    environment: base.environment,
    enabled: base.retentionEnabled,
    mode: base.retentionMode,
    confirmation: env.B2B_RETENTION_CONFIRMATION || "",
    allowProduction: bool(env.B2B_ALLOW_PRODUCTION_RETENTION, false),
    expiredUnlinkedMs: base.retentionExpiredUnlinkedMs,
    syncedPayloadMs: base.retentionSyncedPayloadMs,
    failedUnlinkedMs: base.retentionFailedUnlinkedMs,
    operationalEventsMs: base.retentionOperationalEventsMs,
    batchSize: base.retentionBatchSize,
  };
  if (config.mode === "execute") {
    if (!config.enabled) throw new Error("retention_disabled");
    if (config.confirmation !== RETENTION_EXECUTION_CONFIRMATION) throw new Error("retention_confirmation_required");
    if (config.environment === "production" && !config.allowProduction) throw new Error("retention_production_refused");
  }
  return config;
}
