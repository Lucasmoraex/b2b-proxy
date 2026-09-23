import crypto from "node:crypto";

export const DATA_DIGEST_SECRET_MIN_LENGTH = 32;
export const DATA_DIGEST_VERSION = "hmac-sha256-v1";

const DOMAINS = Object.freeze({
  registrationRequest: "registration-request:v1",
  webhookPayload: "webhook-payload:v1",
  rateLimitAdmission: "rate-limit-admission:v1",
});

export function validateDataDigestSecret(secret) {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < DATA_DIGEST_SECRET_MIN_LENGTH) {
    throw new Error("data_digest_secret_invalid");
  }
  return secret;
}

export function assertDedicatedDataDigestSecret(secret, otherSecrets = []) {
  validateDataDigestSecret(secret);
  if (otherSecrets.some((candidate) => typeof candidate === "string" && candidate && candidate === secret)) {
    throw new Error("data_digest_secret_reuse_forbidden");
  }
  return secret;
}

function hmacDigest(domain, value, secret) {
  validateDataDigestSecret(secret);
  if (typeof value !== "string" && !Buffer.isBuffer(value)) throw new Error("data_digest_input_invalid");
  return crypto.createHmac("sha256", secret)
    .update(`b2b-data-digest\0${domain}\0`)
    .update(value)
    .digest("hex");
}

export function registrationRequestDigest({ email, cnpj, phone }, secret) {
  return hmacDigest(DOMAINS.registrationRequest, JSON.stringify({ email, cnpj, phone }), secret);
}

export function webhookPayloadDigest(rawBody, secret) {
  return hmacDigest(DOMAINS.webhookPayload, rawBody, secret);
}

export function rateLimitAdmissionDigest(requestDigest, secret) {
  return hmacDigest(DOMAINS.rateLimitAdmission, requestDigest, secret);
}
