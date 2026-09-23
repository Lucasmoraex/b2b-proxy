import crypto from "node:crypto";
import { DATA_DIGEST_VERSION, validateDataDigestSecret } from "./data-digests.js";

export const REGISTRATION_IDENTITY_TYPES = Object.freeze(["email", "cnpj", "phone"]);
export const REGISTRATION_IDENTITY_KEY_VERSION = DATA_DIGEST_VERSION;

export const REGISTRATION_IDENTITY_CONFLICT_CODES = Object.freeze({
  email: "email_in_use",
  cnpj: "cnpj_in_use",
  phone: "phone_in_use",
});

export function registrationIdentityHash({ type, normalized, secret }) {
  if (!REGISTRATION_IDENTITY_TYPES.includes(type) || typeof normalized !== "string" || !normalized) {
    throw new Error("registration_identity_input_invalid");
  }
  validateDataDigestSecret(secret);
  return crypto.createHmac("sha256", secret)
    .update(`b2b-registration-identity:${type}:v1\0`)
    .update(normalized)
    .digest("hex");
}

export function buildRegistrationIdentityClaims({ email, cnpj, phone, secret }) {
  const values = { email, cnpj, phone };
  return REGISTRATION_IDENTITY_TYPES.map((type) => ({
    type,
    keyVersion: REGISTRATION_IDENTITY_KEY_VERSION,
    valueHash: registrationIdentityHash({ type, normalized: values[type], secret }),
  }));
}
