import crypto from "node:crypto";
import { extractLegacyNote } from "../audit/customer-audit.js";
import { normalizeBrazilianPhone, normalizeCnpj, normalizeEmail } from "../validation.js";
import { registrationIdentityHash, REGISTRATION_IDENTITY_KEY_VERSION } from "../registration-identities.js";

export const IDENTITY_TYPES = Object.freeze(["email", "cnpj", "phone"]);
export const IDENTITY_INDEX_MIN_SECRET_LENGTH = 32;
export const IDENTITY_IMPORT_CONFIRMATION = "IMPORT_HISTORICAL_IDENTITIES";

const REAL_SHOP_DOMAIN = /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const SYNTHETIC_SHOP_DOMAIN = /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.invalid$/;

const present = (value) => typeof value === "string" && value.trim() !== "";
const metafieldValue = (metafield) => typeof metafield?.value === "string" ? metafield.value.trim() : "";

export function isHistoricalIdentityShopDomain(domain, { allowSynthetic = false } = {}) {
  return typeof domain === "string"
    && (REAL_SHOP_DOMAIN.test(domain) || (allowSynthetic && SYNTHETIC_SHOP_DOMAIN.test(domain)));
}

export function validateIdentityIndexSecret(secret) {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < IDENTITY_INDEX_MIN_SECRET_LENGTH) {
    throw new Error("identity_index_secret_invalid");
  }
  return secret;
}

export function assertDedicatedIdentityIndexSecret(secret, otherSecrets = []) {
  validateIdentityIndexSecret(secret);
  if (otherSecrets.some((candidate) => typeof candidate === "string" && candidate && candidate === secret)) {
    throw new Error("identity_index_secret_reuse_forbidden");
  }
  return secret;
}

export function identityIndexSecretFingerprint(secret) {
  validateIdentityIndexSecret(secret);
  return crypto.createHash("sha256")
    .update("b2b-identity-index-secret:v1\0")
    .update(secret)
    .digest("hex");
}

export function hashHistoricalIdentity({ type, normalized, secret }) {
  if (!IDENTITY_TYPES.includes(type) || typeof normalized !== "string" || !normalized) {
    throw new Error("historical_identity_hash_input_invalid");
  }
  validateIdentityIndexSecret(secret);
  return crypto.createHmac("sha256", secret)
    .update(`b2b-historical-identity:v1\0${type}\0${normalized}`)
    .digest("hex");
}

const collectType = ({ type, candidates, normalizer, secret, registrationIdentitySecret }) => {
  const claims = new Map();
  const presentSources = [];
  let invalid = false;
  for (const [source, raw] of candidates) {
    if (!present(raw)) continue;
    presentSources.push(source);
    try {
      const normalized = normalizer(raw);
      const valueHash = hashHistoricalIdentity({ type, normalized, secret });
      const existing = claims.get(valueHash) || {
        type,
        valueHash,
        normalized,
        registrationKeyVersion: registrationIdentitySecret ? REGISTRATION_IDENTITY_KEY_VERSION : null,
        registrationValueHash: registrationIdentitySecret
          ? registrationIdentityHash({ type, normalized, secret: registrationIdentitySecret })
          : null,
        validity: "valid",
        sources: [],
      };
      existing.sources = [...new Set([...existing.sources, source])].sort();
      claims.set(valueHash, existing);
    } catch {
      invalid = true;
    }
  }
  return {
    claims: [...claims.values()].sort((left, right) => left.valueHash.localeCompare(right.valueHash)),
    state: {
      type,
      validity: claims.size ? "valid" : invalid ? "invalid" : "incomplete",
      sources: presentSources.length ? [...new Set(presentSources)].sort() : candidates.map(([source]) => source).sort(),
    },
  };
};

export function buildHistoricalCustomerIdentityRecord(customer, secret, registrationIdentitySecret = "") {
  validateIdentityIndexSecret(secret);
  if (typeof customer?.id !== "string" || !customer.id || customer.id.length > 256) {
    throw new Error("invalid_shopify_customer_id");
  }
  const legacy = extractLegacyNote(customer.note);
  const groups = [
    collectType({
      type: "email",
      candidates: [["customer.email", customer.email]],
      normalizer: normalizeEmail,
      secret,
      registrationIdentitySecret,
    }),
    collectType({
      type: "cnpj",
      candidates: [
        ["custom.cnpj", metafieldValue(customer.cnpj)],
        ["custom.cjnpj", metafieldValue(customer.cjnpj)],
        ["note", legacy?.cnpj || ""],
      ],
      normalizer: normalizeCnpj,
      secret,
      registrationIdentitySecret,
    }),
    collectType({
      type: "phone",
      candidates: [
        ["customer.phone", customer.phone],
        ["note", legacy?.phone || ""],
      ],
      normalizer: normalizeBrazilianPhone,
      secret,
      registrationIdentitySecret,
    }),
  ];
  return {
    customerId: customer.id,
    claims: groups.flatMap((group) => group.claims),
    states: groups.map((group) => group.state),
  };
}

export function registrationIdentityClaims({ email, cnpj, phone, secret }) {
  return [
    ["email", email],
    ["cnpj", cnpj],
    ["phone", phone],
  ].map(([type, normalized]) => ({
    type,
    normalized,
    valueHash: hashHistoricalIdentity({ type, normalized, secret }),
  }));
}
