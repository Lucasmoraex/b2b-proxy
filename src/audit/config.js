const positiveInteger = (value, fallback, maximum) => {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(String(value))) throw new Error("invalid_audit_configuration");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error("invalid_audit_configuration");
  }
  return parsed;
};

const nonNegativeInteger = (value, fallback, maximum) => {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(String(value))) throw new Error("invalid_audit_configuration");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) {
    throw new Error("invalid_audit_configuration");
  }
  return parsed;
};

export function loadCustomerAuditConfig(env = process.env) {
  if (env.B2B_AUDIT_CONFIRMATION !== "READ_ONLY_CUSTOMER_AUDIT") {
    throw new Error("audit_confirmation_required");
  }
  if (env.B2B_AUDIT_MODE !== "read-only") throw new Error("audit_read_only_mode_required");

  const shopDomain = env.SHOPIFY_SHOP;
  const confirmedDomain = env.B2B_AUDIT_CONFIRMED_SHOP_DOMAIN;
  if (typeof shopDomain !== "string" || typeof confirmedDomain !== "string" || shopDomain !== confirmedDomain) {
    throw new Error("audit_shop_confirmation_mismatch");
  }
  if (!/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(shopDomain)) {
    throw new Error("invalid_audit_shop_domain");
  }
  if (typeof env.SHOPIFY_ADMIN_TOKEN !== "string" || !env.SHOPIFY_ADMIN_TOKEN) {
    throw new Error("audit_shopify_token_required");
  }
  const apiVersion = env.SHOPIFY_API_VERSION || "2026-07";
  if (!/^20\d{2}-(?:01|04|07|10)$/.test(apiVersion)) throw new Error("invalid_audit_api_version");

  return {
    shopDomain,
    token: env.SHOPIFY_ADMIN_TOKEN,
    apiVersion,
    timeoutMs: positiveInteger(env.B2B_AUDIT_TIMEOUT_MS, 8000, 60_000),
    maxRetries: nonNegativeInteger(env.B2B_AUDIT_MAX_RETRIES, 4, 10),
  };
}
