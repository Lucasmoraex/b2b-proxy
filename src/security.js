import crypto from "node:crypto";

export function timingSafeEqualText(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || !left || !right) return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function verifyShopifyHmac(rawBody, suppliedHmac, secret) {
  if (!Buffer.isBuffer(rawBody) || !suppliedHmac || !secret) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  let supplied;
  try {
    supplied = Buffer.from(suppliedHmac, "base64");
  } catch {
    return false;
  }
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

export function signRegistrationToken(registration, secret) {
  return crypto.createHmac("sha256", secret).update(`${registration.id}:${new Date(registration.expires_at).toISOString()}`).digest("base64url");
}

export function verifyRegistrationToken({ registration, suppliedToken, secret, now, clockToleranceMs = 0 }) {
  if (!registration || typeof suppliedToken !== "string" || !suppliedToken || typeof secret !== "string" || !secret) return false;
  const expiresAtMs = new Date(registration.expires_at).getTime();
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  if (!Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs)
    || !Number.isInteger(clockToleranceMs) || clockToleranceMs < 0) return false;
  // The tolerance is fail-closed: tokens expire slightly early and never after expires_at.
  if (nowMs + clockToleranceMs >= expiresAtMs) return false;
  return timingSafeEqualText(suppliedToken, signRegistrationToken(registration, secret));
}

const PERSISTED_ERROR_CODES = new Set([
  "historical_identity_import_failed",
  "historical_identity_index_unavailable",
  "historical_identity_registration_conflict",
  "missing_customer_binding",
  "operation_failed",
  "payload_purged",
  "payload_unavailable",
  "registration_not_ready",
  "registry_unavailable",
  "shopify_audit_pagination_failed",
  "shopify_audit_query_failed",
  "shopify_audit_unavailable",
  "shopify_customer_not_found",
  "shopify_operation_failed",
  "shopify_unavailable",
  "unknown_operation",
]);

const PERSISTED_ERROR_CATEGORIES = new Set([
  "conflict", "historical_identity", "internal", "registry", "shopify", "validation",
]);

const inferErrorCategory = (code, fallback) => {
  if (code.startsWith("shopify_")) return "shopify";
  if (code.startsWith("registry_")) return "registry";
  if (code.startsWith("historical_identity_")) return code.endsWith("conflict") ? "conflict" : "historical_identity";
  if (code === "registration_not_ready") return "validation";
  return PERSISTED_ERROR_CATEGORIES.has(fallback) ? fallback : "internal";
};

export function persistedErrorRecord(error, { defaultCategory = "internal" } = {}) {
  const candidate = typeof error?.code === "string" ? error.code : "operation_failed";
  const code = PERSISTED_ERROR_CODES.has(candidate) ? candidate : "operation_failed";
  const category = inferErrorCategory(code, defaultCategory);
  const upstreamStatus = Number.isInteger(error?.upstreamStatus)
    && error.upstreamStatus >= 100 && error.upstreamStatus <= 599
    ? error.upstreamStatus
    : null;
  return { code, category, upstreamStatus };
}
