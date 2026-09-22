import crypto from "node:crypto";
import { createApp } from "../src/app.js";
import { createLogger } from "../src/logger.js";
import { MemoryRegistrationStore } from "../src/storage/memory-store.js";

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
    allowedOrigins: [], rateLimitWindowMs: 60_000, rateLimitMax: 1000,
    reservationTtlMs: 30 * 60 * 1000,
    registrationTokenSecret: "test-registration-secret-not-production",
    shopifyWebhookSecret: "test-webhook-secret-not-production",
    adminSecret: "test-admin-secret-not-production",
    enableLegacyMutations: false, enableLegacyLogin: false,
    ...options.config,
  };
  const app = createApp({ config, store, registryClient, logger, clock, legacyMutationHandler: options.legacyMutationHandler });
  return { app, store, logger, lines, clock, setNow, config, registryClient, get registryCalls() { return registryCalls; } };
}

export const newKey = () => crypto.randomUUID();
export const defaultPayload = (overrides = {}) => ({
  email: "empresa@example.invalid",
  cnpj: makeCnpj(),
  phone: "+5511999990001",
  ...overrides,
});
