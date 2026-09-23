import { assertDedicatedIdentityIndexSecret, isHistoricalIdentityShopDomain } from "./historical-identities.js";
import { assertDedicatedDataDigestSecret } from "../data-digests.js";

const bool = (value, fallback = false) => {
  if (value === undefined || value === "") return fallback;
  return String(value).toLowerCase() === "true";
};

const positiveInteger = (value, fallback, maximum) => {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(String(value))) throw new Error("invalid_identity_import_configuration");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error("invalid_identity_import_configuration");
  }
  return parsed;
};

const nonNegativeInteger = (value, fallback, maximum) => {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(String(value))) throw new Error("invalid_identity_import_configuration");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) {
    throw new Error("invalid_identity_import_configuration");
  }
  return parsed;
};

export function loadHistoricalIdentityImportConfig(env = process.env) {
  const mode = env.B2B_IDENTITY_IMPORT_MODE || "dry-run";
  if (!["dry-run", "write"].includes(mode)) throw new Error("identity_import_mode_invalid");
  const shopDomain = env.SHOPIFY_SHOP;
  const confirmedDomain = env.B2B_IDENTITY_IMPORT_CONFIRMED_SHOP_DOMAIN;
  if (typeof shopDomain !== "string" || shopDomain !== confirmedDomain) {
    throw new Error("identity_import_shop_confirmation_mismatch");
  }
  if (!isHistoricalIdentityShopDomain(shopDomain)) {
    throw new Error("identity_import_shop_invalid");
  }
  if (typeof env.SHOPIFY_ADMIN_TOKEN !== "string" || !env.SHOPIFY_ADMIN_TOKEN) {
    throw new Error("identity_import_shopify_token_required");
  }
  assertDedicatedIdentityIndexSecret(env.B2B_IDENTITY_INDEX_SECRET, [
    env.B2B_ADMIN_SECRET,
    env.B2B_REGISTRATION_TOKEN_SECRET,
    env.SHOPIFY_WEBHOOK_SECRET,
    env.B2B_DATA_DIGEST_SECRET,
    env.B2B_RATE_LIMIT_KEY_SECRET,
  ]);

  const environment = env.B2B_ENVIRONMENT || "production";
  if (mode === "write") {
    assertDedicatedDataDigestSecret(env.B2B_DATA_DIGEST_SECRET, [
      env.B2B_ADMIN_SECRET,
      env.B2B_REGISTRATION_TOKEN_SECRET,
      env.SHOPIFY_WEBHOOK_SECRET,
      env.B2B_IDENTITY_INDEX_SECRET,
      env.B2B_RATE_LIMIT_KEY_SECRET,
    ]);
    if (!bool(env.B2B_ENABLE_HISTORICAL_IDENTITY_IMPORT, false)) {
      throw new Error("identity_import_disabled");
    }
    if (env.B2B_IDENTITY_IMPORT_CONFIRMATION !== "IMPORT_HISTORICAL_IDENTITIES") {
      throw new Error("identity_import_confirmation_required");
    }
    if (environment === "production" && !bool(env.B2B_ALLOW_PRODUCTION_IDENTITY_IMPORT, false)) {
      throw new Error("identity_import_production_refused");
    }
    if (!env.DATABASE_URL) throw new Error("identity_import_database_required");
  }

  const apiVersion = env.SHOPIFY_API_VERSION || "2026-07";
  if (!/^20\d{2}-(?:01|04|07|10)$/.test(apiVersion)) throw new Error("identity_import_api_version_invalid");
  return {
    mode,
    dryRun: mode === "dry-run",
    environment,
    shopDomain,
    token: env.SHOPIFY_ADMIN_TOKEN,
    apiVersion,
    identityIndexSecret: env.B2B_IDENTITY_INDEX_SECRET,
    registrationIdentitySecret: mode === "write" ? env.B2B_DATA_DIGEST_SECRET : "",
    confirmation: env.B2B_IDENTITY_IMPORT_CONFIRMATION || "",
    databaseUrl: mode === "write" ? env.DATABASE_URL : "",
    databaseSsl: bool(env.DATABASE_SSL, false),
    timeoutMs: positiveInteger(env.B2B_IDENTITY_IMPORT_TIMEOUT_MS, 8000, 60_000),
    maxRetries: nonNegativeInteger(env.B2B_IDENTITY_IMPORT_MAX_RETRIES, 4, 10),
  };
}
