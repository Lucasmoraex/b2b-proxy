import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import {
  assertDedicatedDataDigestSecret,
  DATA_DIGEST_VERSION,
  rateLimitAdmissionDigest,
  registrationRequestDigest,
  webhookPayloadDigest,
} from "../src/data-digests.js";
import { loadConfig } from "../src/config.js";
import { createLogger } from "../src/logger.js";
import { buildWebRuntime } from "../src/runtime.js";
import { persistedErrorRecord } from "../src/security.js";

test("versioned data digests use a dedicated HMAC secret and separated domains", () => {
  const secret = "synthetic-data-digest-secret-minimum-32-characters";
  const normalized = {
    email: "digest@example.invalid",
    cnpj: "12345678901230",
    phone: "+5511999990001",
    employee_range: "10-29",
  };
  const request = registrationRequestDigest(normalized, secret);
  const serialized = JSON.stringify(normalized);
  const webhook = webhookPayloadDigest(Buffer.from(serialized), secret);
  const admission = rateLimitAdmissionDigest(request, secret);
  assert.equal(DATA_DIGEST_VERSION, "hmac-sha256-v1");
  for (const value of [request, webhook, admission]) assert.match(value, /^[0-9a-f]{64}$/);
  assert.equal(new Set([request, webhook, admission]).size, 3);
  assert.notEqual(request, crypto.createHash("sha256").update(serialized).digest("hex"));
  assert.throws(() => assertDedicatedDataDigestSecret("too-short"), /data_digest_secret_invalid/);
  assert.throws(() => assertDedicatedDataDigestSecret(secret, [secret]), /data_digest_secret_reuse_forbidden/);
});

test("production web runtime refuses missing or reused data digest secret before opening the store", () => {
  const base = {
    B2B_ENVIRONMENT: "production",
    DATABASE_URL: "postgres://local.invalid/never-opened",
    B2B_ALLOWED_ORIGIN: "https://portal.example.invalid",
    B2B_TRUST_PROXY_HOPS: "1",
    SHOPIFY_WEBHOOK_SECRET: "synthetic-webhook-secret-minimum-32-characters",
    B2B_ADMIN_SECRET: "synthetic-admin-secret-minimum-32-characters",
    B2B_REGISTRATION_TOKEN_SECRET: "synthetic-registration-token-secret-minimum-32",
    B2B_RATE_LIMIT_KEY_SECRET: "synthetic-rate-limit-secret-minimum-32-characters",
    B2B_PII_ENCRYPTION_ACTIVE_KEY_VERSION: "test-v1",
    B2B_PII_ENCRYPTION_KEYS: JSON.stringify({
      "test-v1": Buffer.from("0123456789abcdef0123456789abcdef").toString("base64"),
    }),
  };
  assert.throws(() => buildWebRuntime({ env: base }), /B2B_DATA_DIGEST_SECRET/);
  assert.throws(() => buildWebRuntime({
    env: { ...base, B2B_DATA_DIGEST_SECRET: base.B2B_ADMIN_SECRET },
  }), /data_digest_secret_reuse_forbidden/);
  assert.throws(() => buildWebRuntime({
    env: { ...base, B2B_DATA_DIGEST_SECRET: "synthetic-data-digest-secret-minimum-32", B2B_DATA_DIGEST_VERSION: "legacy" },
  }), /data_digest_version_invalid/);
});

test("registration token clock tolerance is small and validated", () => {
  assert.equal(loadConfig({ B2B_REGISTRATION_TOKEN_CLOCK_TOLERANCE_MS: "0" }).registrationTokenClockToleranceMs, 0);
  assert.equal(loadConfig({}).registrationTokenClockToleranceMs, 1000);
  assert.throws(() => loadConfig({ B2B_REGISTRATION_TOKEN_CLOCK_TOLERANCE_MS: "5001" }), /B2B_REGISTRATION_TOKEN_CLOCK_TOLERANCE_MS_invalid/);
});

test("logger persists only allowlisted scalar fields and drops free-form or nested data", () => {
  const lines = [];
  const sink = { log: (line) => lines.push(line), warn: (line) => lines.push(line), error: (line) => lines.push(line) };
  const logger = createLogger(sink);
  const privateValue = "private-person@example.invalid";
  logger.warn("privacy_test", {
    requestId: "request-123",
    method: "POST",
    path: "/v1/registrations/:id",
    status: 401,
    elapsedMs: 12,
    operation: "sync_registration",
    code: "unauthorized",
    category: "request",
    attempt: 2,
    attempts: 3,
    terminal: false,
    error: Object.assign(new Error(privateValue), { code: "misleading_safe_name" }),
    nested: { code: "safe_looking", value: privateValue },
    array: [privateValue, { code: "safe_looking" }],
    url: `https://example.invalid/path?email=${privateValue}`,
    headers: { authorization: "Bearer secret" },
    codeWithMisleadingName: privateValue,
    reason: privateValue,
  });
  const parsed = JSON.parse(lines[0]);
  assert.deepEqual(parsed, {
    level: "warn",
    event: "privacy_test",
    requestId: "request-123",
    method: "POST",
    path: "/v1/registrations/:id",
    status: 401,
    elapsedMs: 12,
    operation: "sync_registration",
    code: "unauthorized",
    category: "request",
    attempt: 2,
    attempts: 3,
    terminal: false,
  });
  assert.equal(lines[0].includes(privateValue), false);
  assert.equal(lines[0].includes("Bearer"), false);
});

test("logger rejects URLs in path, arrays, Error instances and deceptive event names", () => {
  const lines = [];
  const logger = createLogger({ log: (line) => lines.push(line), warn: (line) => lines.push(line), error: (line) => lines.push(line) });
  logger.error("unsafe event with spaces", {
    path: "https://example.invalid/customers/1?token=secret",
    code: ["operation_failed"],
    category: new Error("secret"),
    status: "500",
  });
  assert.deepEqual(JSON.parse(lines[0]), { level: "error", event: "invalid_log_event" });
});

test("persisted errors are allowlisted structures without message, stack, SQL or payload", () => {
  const error = Object.assign(new Error("private@example.invalid SELECT * FROM registrations"), {
    code: "shopify_unavailable",
    upstreamStatus: 503,
    payload: { token: "secret" },
  });
  const safe = persistedErrorRecord(error, { defaultCategory: "shopify" });
  assert.deepEqual(safe, { code: "shopify_unavailable", category: "shopify", upstreamStatus: 503 });
  assert.equal(JSON.stringify(safe).includes("private"), false);
  assert.deepEqual(persistedErrorRecord(Object.assign(new Error("secret"), { code: "made_up" })), {
    code: "operation_failed", category: "internal", upstreamStatus: null,
  });
});
