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

export function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function signRegistrationToken(registration, secret) {
  return crypto.createHmac("sha256", secret).update(`${registration.id}:${new Date(registration.expires_at).toISOString()}`).digest("base64url");
}

const SENSITIVE_KEY = /(email|cnpj|phone|secret|token|authorization|query|payload|body|metafield|value)/i;

export function redact(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  if (typeof value !== "object") return value;
  if (seen.has(value)) return "[circular]";
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => redact(item, seen));
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, SENSITIVE_KEY.test(key) ? "[redacted]" : redact(item, seen)]));
}

export function sanitizeError(error) {
  return JSON.stringify({
    name: String(error?.name || "Error").slice(0, 80),
    code: String(error?.code || "operation_failed").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 80),
    status: Number.isInteger(error?.status) ? error.status : undefined,
  });
}
