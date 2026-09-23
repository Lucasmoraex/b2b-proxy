const bool = (value, fallback = false) => {
  if (value === undefined || value === "") return fallback;
  return String(value).toLowerCase() === "true";
};

import { parseAllowedOrigins } from "./http-security.js";
import { DATA_DIGEST_VERSION } from "./data-digests.js";

const int = (value, fallback, name, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) => {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(String(value))) throw new Error(`${name}_invalid`);
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name}_invalid`);
  return parsed;
};

export function loadConfig(env = process.env) {
  const environment = env.B2B_ENVIRONMENT || "production";
  return {
    environment,
    nodeEnv: env.NODE_ENV || "production",
    isRender: String(env.RENDER || "").toLowerCase() === "true",
    renderServiceName: env.RENDER_SERVICE_NAME || "",
    port: int(env.PORT, 3000, "PORT", { max: 65535 }),
    databaseUrl: env.DATABASE_URL || "",
    databaseSsl: bool(env.DATABASE_SSL, false),
    shop: env.SHOPIFY_SHOP || "",
    shopifyToken: env.SHOPIFY_ADMIN_TOKEN || "",
    shopifyClientId: env.SHOPIFY_CLIENT_ID || "",
    shopifyClientSecret: env.SHOPIFY_CLIENT_SECRET || "",
    shopifyApiVersion: env.SHOPIFY_API_VERSION || "2026-07",
    shopifyWebhookSecret: env.SHOPIFY_WEBHOOK_SECRET || "",
    adminSecret: env.B2B_ADMIN_SECRET || "",
    registrationTokenSecret: env.B2B_REGISTRATION_TOKEN_SECRET || "",
    registrationTokenClockToleranceMs: int(env.B2B_REGISTRATION_TOKEN_CLOCK_TOLERANCE_MS, 1000, "B2B_REGISTRATION_TOKEN_CLOCK_TOLERANCE_MS", { min: 0, max: 5000 }),
    dataDigestSecret: env.B2B_DATA_DIGEST_SECRET || "",
    dataDigestVersion: env.B2B_DATA_DIGEST_VERSION || DATA_DIGEST_VERSION,
    piiEncryptionActiveKeyVersion: env.B2B_PII_ENCRYPTION_ACTIVE_KEY_VERSION || "",
    piiEncryptionKeys: env.B2B_PII_ENCRYPTION_KEYS || "",
    rateLimitKeySecret: env.B2B_RATE_LIMIT_KEY_SECRET || "",
    registryBaseUrl: env.B2B_RECEITAWS_BASE || "https://www.receitaws.com.br/v1",
    registryToken: env.B2B_RECEITAWS_TOKEN || "",
    registryTokenMode: (env.B2B_RECEITAWS_TOKEN_MODE || "bearer").toLowerCase(),
    allowedOrigins: parseAllowedOrigins(env.B2B_ALLOWED_ORIGIN || ""),
    autoApprove: bool(env.B2B_AUTO_APPROVE, false),
    enableLegacyMutations: bool(env.B2B_ENABLE_LEGACY_MUTATIONS, false),
    enableLegacyLogin: bool(env.B2B_ENABLE_LEGACY_LOGIN, false),
    enableHistoricalIdentityLookup: bool(env.B2B_ENABLE_HISTORICAL_IDENTITY_LOOKUP, false),
    identityIndexSecret: env.B2B_IDENTITY_INDEX_SECRET || "",
    requestTimeoutMs: int(env.B2B_REQUEST_TIMEOUT_MS, 8000, "B2B_REQUEST_TIMEOUT_MS", { max: 120_000 }),
    reservationTtlMs: int(env.B2B_RESERVATION_TTL_MS, 30 * 60 * 1000, "B2B_RESERVATION_TTL_MS", { max: 24 * 60 * 60 * 1000 }),
    fiscalCacheTtlMs: int(env.B2B_FISCAL_CACHE_TTL_MS, 24 * 60 * 60 * 1000, "B2B_FISCAL_CACHE_TTL_MS", { max: 30 * 24 * 60 * 60 * 1000 }),
    rateLimitWindowMs: int(env.B2B_RATE_LIMIT_WINDOW_MS, 60_000, "B2B_RATE_LIMIT_WINDOW_MS", { max: 60 * 60 * 1000 }),
    rateLimitMax: int(env.B2B_RATE_LIMIT_MAX, 30, "B2B_RATE_LIMIT_MAX", { max: 10_000 }),
    sharedRateLimitWindowMs: int(env.B2B_SHARED_RATE_LIMIT_WINDOW_MS, 60_000, "B2B_SHARED_RATE_LIMIT_WINDOW_MS", { max: 60 * 60 * 1000 }),
    sharedRateLimitMax: int(env.B2B_SHARED_RATE_LIMIT_MAX, 20, "B2B_SHARED_RATE_LIMIT_MAX", { max: 10_000 }),
    identityRateLimitWindowMs: int(env.B2B_IDENTITY_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000, "B2B_IDENTITY_RATE_LIMIT_WINDOW_MS", { max: 24 * 60 * 60 * 1000 }),
    identityRateLimitMax: int(env.B2B_IDENTITY_RATE_LIMIT_MAX, 10, "B2B_IDENTITY_RATE_LIMIT_MAX", { max: 10_000 }),
    activeReservationsPerIpMax: int(env.B2B_ACTIVE_RESERVATIONS_PER_IP_MAX, 5, "B2B_ACTIVE_RESERVATIONS_PER_IP_MAX", { max: 1_000 }),
    rateLimitStateRetentionMs: int(env.B2B_RATE_LIMIT_STATE_RETENTION_MS, 24 * 60 * 60 * 1000, "B2B_RATE_LIMIT_STATE_RETENTION_MS", { max: 30 * 24 * 60 * 60 * 1000 }),
    rateLimitCleanupBatchSize: int(env.B2B_RATE_LIMIT_CLEANUP_BATCH_SIZE, 200, "B2B_RATE_LIMIT_CLEANUP_BATCH_SIZE", { max: 10_000 }),
    jsonBodyLimitBytes: int(env.B2B_JSON_BODY_LIMIT_BYTES, 8192, "B2B_JSON_BODY_LIMIT_BYTES", { min: 1024, max: 65_536 }),
    webhookBodyLimitBytes: int(env.B2B_WEBHOOK_BODY_LIMIT_BYTES, 262_144, "B2B_WEBHOOK_BODY_LIMIT_BYTES", { min: 1024, max: 1_048_576 }),
    headerTimeoutMs: int(env.B2B_HEADER_TIMEOUT_MS, 10_000, "B2B_HEADER_TIMEOUT_MS", { min: 1000, max: 120_000 }),
    httpRequestTimeoutMs: int(env.B2B_HTTP_REQUEST_TIMEOUT_MS, 15_000, "B2B_HTTP_REQUEST_TIMEOUT_MS", { min: 1000, max: 300_000 }),
    keepAliveTimeoutMs: int(env.B2B_KEEP_ALIVE_TIMEOUT_MS, 5000, "B2B_KEEP_ALIVE_TIMEOUT_MS", { min: 1000, max: 120_000 }),
    trustProxyHops: int(env.B2B_TRUST_PROXY_HOPS, 0, "B2B_TRUST_PROXY_HOPS", { min: 0, max: 10 }),
    trustProxyConfigured: env.B2B_TRUST_PROXY_HOPS !== undefined && env.B2B_TRUST_PROXY_HOPS !== "",
    workerPollMs: int(env.B2B_WORKER_POLL_MS, 2000, "B2B_WORKER_POLL_MS", { max: 60_000 }),
    workerMaxAttempts: int(env.B2B_WORKER_MAX_ATTEMPTS, 8, "B2B_WORKER_MAX_ATTEMPTS", { max: 100 }),
    retentionEnabled: bool(env.B2B_RETENTION_ENABLED, false),
    retentionMode: env.B2B_RETENTION_MODE || "report-only",
    retentionExpiredUnlinkedMs: int(env.B2B_RETENTION_EXPIRED_UNLINKED_MS, 24 * 60 * 60 * 1000, "B2B_RETENTION_EXPIRED_UNLINKED_MS", { max: 365 * 24 * 60 * 60 * 1000 }),
    retentionSyncedPayloadMs: int(env.B2B_RETENTION_SYNCED_PAYLOAD_MS, 7 * 24 * 60 * 60 * 1000, "B2B_RETENTION_SYNCED_PAYLOAD_MS", { max: 365 * 24 * 60 * 60 * 1000 }),
    retentionFailedUnlinkedMs: int(env.B2B_RETENTION_FAILED_UNLINKED_MS, 30 * 24 * 60 * 60 * 1000, "B2B_RETENTION_FAILED_UNLINKED_MS", { max: 5 * 365 * 24 * 60 * 60 * 1000 }),
    retentionOperationalEventsMs: int(env.B2B_RETENTION_OPERATIONAL_EVENTS_MS, 30 * 24 * 60 * 60 * 1000, "B2B_RETENTION_OPERATIONAL_EVENTS_MS", { max: 5 * 365 * 24 * 60 * 60 * 1000 }),
    retentionBatchSize: int(env.B2B_RETENTION_BATCH_SIZE, 200, "B2B_RETENTION_BATCH_SIZE", { max: 10_000 }),
    simulationMode: bool(env.B2B_SIMULATION_MODE, false),
    simulationConfirmation: env.B2B_SIMULATION_CONFIRMATION || "",
    simulatedRegistryScenario: env.B2B_SIMULATED_REGISTRY_SCENARIO || "active",
  };
}
