import crypto from "node:crypto";

export const PII_ENCRYPTION_PURPOSE = "registration-operational-payload:v1";
const VERSION = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;

const decodeKey = (encoded) => {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new Error("pii_encryption_key_invalid");
  }
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32 || key.toString("base64") !== encoded) throw new Error("pii_encryption_key_invalid");
  return key;
};

export function createPiiEncryptionKeyring({ activeVersion, serializedKeys, otherSecrets = [] }) {
  if (typeof activeVersion !== "string" || !VERSION.test(activeVersion)) {
    throw new Error("pii_encryption_active_key_version_invalid");
  }
  let parsed;
  try { parsed = JSON.parse(serializedKeys); } catch { throw new Error("pii_encryption_keys_invalid"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Object.keys(parsed).length) {
    throw new Error("pii_encryption_keys_invalid");
  }
  const keys = new Map();
  for (const [version, encoded] of Object.entries(parsed)) {
    if (!VERSION.test(version) || keys.has(version)) throw new Error("pii_encryption_key_version_invalid");
    const key = decodeKey(encoded);
    if ([...keys.values()].some((existing) => crypto.timingSafeEqual(existing, key))) {
      throw new Error("pii_encryption_key_reuse_forbidden");
    }
    for (const secret of otherSecrets) {
      if (typeof secret !== "string" || !secret) continue;
      const candidate = Buffer.from(secret, "utf8");
      if (candidate.length === key.length && crypto.timingSafeEqual(candidate, key)) {
        throw new Error("pii_encryption_key_reuse_forbidden");
      }
    }
    keys.set(version, key);
  }
  if (!keys.has(activeVersion)) throw new Error("pii_encryption_active_key_missing");
  return Object.freeze({ activeVersion, keys });
}

const aad = (registrationId) => Buffer.from(`b2b:${PII_ENCRYPTION_PURPOSE}\0${registrationId}`, "utf8");

export function encryptRegistrationOperationalPayload({ registrationId, payload, keyring, randomBytes = crypto.randomBytes }) {
  const key = keyring?.keys?.get(keyring.activeVersion);
  if (!key) throw new Error("pii_encryption_key_unavailable");
  const nonce = randomBytes(12);
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) throw new Error("pii_encryption_nonce_invalid");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad(registrationId));
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext,
    nonce,
    authTag: cipher.getAuthTag(),
    encryptionKeyVersion: keyring.activeVersion,
  };
}

export function decryptRegistrationOperationalPayload({ registrationId, encrypted, keyring }) {
  if (!encrypted || encrypted.purged_at) throw new Error("payload_purged");
  const version = encrypted.encryption_key_version || encrypted.encryptionKeyVersion;
  const key = keyring?.keys?.get(version);
  if (!key) throw new Error("pii_encryption_key_unavailable");
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(encrypted.nonce));
    decipher.setAAD(aad(registrationId));
    decipher.setAuthTag(Buffer.from(encrypted.auth_tag || encrypted.authTag));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(encrypted.ciphertext)), decipher.final()]);
    const payload = JSON.parse(plaintext.toString("utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid");
    return payload;
  } catch (error) {
    if (error?.message === "payload_purged" || error?.message === "pii_encryption_key_unavailable") throw error;
    throw new Error("pii_payload_authentication_failed");
  }
}
