const bool = (value, fallback = false) => {
  if (value === undefined || value === "") return fallback;
  return String(value).toLowerCase() === "true";
};

const int = (value, fallback) => {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

export function loadConfig(env = process.env) {
  return {
    port: int(env.PORT, 3000),
    databaseUrl: env.DATABASE_URL || "",
    databaseSsl: bool(env.DATABASE_SSL, false),
    shop: env.SHOPIFY_SHOP || "",
    shopifyToken: env.SHOPIFY_ADMIN_TOKEN || "",
    shopifyApiVersion: env.SHOPIFY_API_VERSION || "2026-07",
    shopifyWebhookSecret: env.SHOPIFY_WEBHOOK_SECRET || "",
    adminSecret: env.B2B_ADMIN_SECRET || "",
    registrationTokenSecret: env.B2B_REGISTRATION_TOKEN_SECRET || "",
    registryBaseUrl: env.B2B_RECEITAWS_BASE || "https://www.receitaws.com.br/v1",
    registryToken: env.B2B_RECEITAWS_TOKEN || "",
    registryTokenMode: (env.B2B_RECEITAWS_TOKEN_MODE || "bearer").toLowerCase(),
    allowedOrigins: String(env.B2B_ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean),
    autoApprove: bool(env.B2B_AUTO_APPROVE, false),
    enableLegacyMutations: bool(env.B2B_ENABLE_LEGACY_MUTATIONS, false),
    enableLegacyLogin: bool(env.B2B_ENABLE_LEGACY_LOGIN, false),
    requestTimeoutMs: int(env.B2B_REQUEST_TIMEOUT_MS, 8000),
    reservationTtlMs: int(env.B2B_RESERVATION_TTL_MS, 30 * 60 * 1000),
    rateLimitWindowMs: int(env.B2B_RATE_LIMIT_WINDOW_MS, 60_000),
    rateLimitMax: int(env.B2B_RATE_LIMIT_MAX, 30),
    workerPollMs: int(env.B2B_WORKER_POLL_MS, 2000),
    workerMaxAttempts: int(env.B2B_WORKER_MAX_ATTEMPTS, 8),
  };
}
