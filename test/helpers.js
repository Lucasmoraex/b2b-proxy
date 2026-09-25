import crypto from "node:crypto";
import { createApp } from "../src/app.js";
import { createLogger } from "../src/logger.js";
import { MemoryRegistrationStore } from "../src/storage/memory-store.js";
import { createPiiEncryptionKeyring } from "../src/pii-crypto.js";

export function makeCnpj(base = "123456789012") {
  const calculate = (value) => {
    let sum = 0; let factor = value.length - 7;
    for (const digit of value) { sum += Number(digit) * factor--; if (factor < 2) factor = 9; }
    const remainder = sum % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };
  const first = calculate(base);
  return `${base}${first}${calculate(`${base}${first}`)}`;
}

export function maskCnpj(cnpj) {
  return `${cnpj.slice(0, 2)}.${cnpj.slice(2, 5)}.${cnpj.slice(5, 8)}/${cnpj.slice(8, 12)}-${cnpj.slice(12)}`;
}

export function makeTestContext(options = {}) {
  let now = options.now || new Date("2030-01-01T00:00:00.000Z");
  const clock = () => new Date(now);
  const setNow = (value) => { now = new Date(value); };
  const lines = [];
  const sink = { log: (line) => lines.push(line), warn: (line) => lines.push(line), error: (line) => lines.push(line) };
  const logger = createLogger(sink);
  const store = options.store || new MemoryRegistrationStore({ clock });
  let registryCalls = 0;
  const registryClient = options.registryClient || {
    async checkCnpj() { registryCalls += 1; return { found: true, active: true, status: "ATIVA" }; },
  };
  const config = {
    environment: "test", nodeEnv: "test",
    allowedOrigins: ["https://theme.example.invalid"],
    trustProxyHops: 0, trustProxyConfigured: true,
    rateLimitWindowMs: 60_000, rateLimitMax: 1000,
    sharedRateLimitWindowMs: 60_000, sharedRateLimitMax: 1000,
    identityRateLimitWindowMs: 60_000, identityRateLimitMax: 1000,
    activeReservationsPerIpMax: 1000,
    rateLimitStateRetentionMs: 24 * 60 * 60 * 1000,
    rateLimitCleanupBatchSize: 200,
    jsonBodyLimitBytes: 8192, webhookBodyLimitBytes: 262_144,
    headerTimeoutMs: 10_000, httpRequestTimeoutMs: 15_000, keepAliveTimeoutMs: 5000,
    reservationTtlMs: 30 * 60 * 1000,
    fiscalCacheTtlMs: 60 * 60 * 1000,
    registrationTokenSecret: "test-registration-secret-not-production",
    registrationTokenClockToleranceMs: 1000,
    dataDigestSecret: "test-data-digest-secret-not-production-minimum-32",
    piiEncryptionActiveKeyVersion: "test-v1",
    piiEncryptionKeys: JSON.stringify({
      "test-v1": Buffer.from("0123456789abcdef0123456789abcdef", "utf8").toString("base64"),
    }),
    shopifyWebhookSecret: "test-webhook-secret-not-production",
    adminSecret: "test-admin-secret-not-production",
    rateLimitKeySecret: "test-rate-limit-key-secret-not-production-minimum-32",
    enableLegacyMutations: false, enableLegacyLogin: false,
    simulationMode: false,
    ...options.config,
  };
  const piiKeyring = options.piiKeyring || createPiiEncryptionKeyring({
    activeVersion: config.piiEncryptionActiveKeyVersion,
    serializedKeys: config.piiEncryptionKeys,
    otherSecrets: [
      config.registrationTokenSecret, config.dataDigestSecret, config.shopifyWebhookSecret,
      config.adminSecret, config.rateLimitKeySecret,
    ],
  });
  const app = createApp({
    config, store, registryClient, logger, clock, piiKeyring,
    legacyMutationHandler: options.legacyMutationHandler,
    simulationController: options.simulationController,
  });
  return { app, store, logger, lines, clock, setNow, config, piiKeyring, registryClient, get registryCalls() { return registryCalls; } };
}

export const newKey = () => crypto.randomUUID();
export const defaultPayload = (overrides = {}) => ({
  email: "empresa@example.invalid",
  cnpj: makeCnpj(),
  phone: "+5511999990001",
  employee_range: "10-29",
  ...overrides,
});
