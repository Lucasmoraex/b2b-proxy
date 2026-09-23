import crypto from "node:crypto";
import { rateLimitAdmissionDigest } from "./data-digests.js";

export const RATE_LIMIT_KEY_SECRET_MIN_LENGTH = 32;

export function validateRateLimitKeySecret(secret) {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < RATE_LIMIT_KEY_SECRET_MIN_LENGTH) {
    throw new Error("rate_limit_key_secret_invalid");
  }
  return secret;
}

export function assertDedicatedRateLimitKeySecret(secret, otherSecrets = []) {
  validateRateLimitKeySecret(secret);
  if (otherSecrets.some((candidate) => typeof candidate === "string" && candidate && candidate === secret)) {
    throw new Error("rate_limit_key_secret_reuse_forbidden");
  }
  return secret;
}

export function normalizeClientIp(value) {
  const candidate = typeof value === "string" && value.trim() ? value.trim().toLowerCase() : "unknown";
  return candidate.startsWith("::ffff:") ? candidate.slice(7) : candidate;
}

export function hashRateLimitKey({ secret, scope, value }) {
  validateRateLimitKeySecret(secret);
  if (typeof scope !== "string" || !scope || typeof value !== "string" || !value) {
    throw new Error("rate_limit_key_input_invalid");
  }
  return crypto.createHmac("sha256", secret)
    .update(`b2b-rate-limit:v1\0${scope}\0${value}`)
    .digest("hex");
}

export function hashClientIp(ip, secret) {
  return hashRateLimitKey({ secret, scope: "client-ip", value: normalizeClientIp(ip) });
}

export function registrationRateLimitIdentityKeys({ email, cnpj, phone, secret }) {
  return [
    ["email", email],
    ["cnpj", cnpj],
    ["phone", phone],
  ].map(([type, normalized]) => ({
    type,
    keyHash: hashRateLimitKey({ secret, scope: `registration-identity:${type}`, value: normalized }),
  }));
}

export function registrationAdmissionDigest(requestDigest, secret) {
  return rateLimitAdmissionDigest(requestDigest, secret);
}
