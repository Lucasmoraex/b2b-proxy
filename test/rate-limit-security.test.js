import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import request from "supertest";
import { configureHttpServerTimeouts } from "../src/http-security.js";
import { assertWebHttpSecurityConfig } from "../src/http-security.js";
import { loadConfig } from "../src/config.js";
import {
  assertDedicatedRateLimitKeySecret,
  hashClientIp,
  hashRateLimitKey,
} from "../src/rate-limit.js";
import { ExternalServiceError } from "../src/errors.js";
import { MemoryRegistrationStore } from "../src/storage/memory-store.js";
import { defaultPayload, makeCnpj, makeTestContext, newKey } from "./helpers.js";

const post = (ctx, payload, key = newKey(), headers = {}) => {
  let call = request(ctx.app).post("/v1/registrations").set("Idempotency-Key", key);
  for (const [name, value] of Object.entries(headers)) call = call.set(name, value);
  return call.send(payload);
};

const uniquePayload = (index) => defaultPayload({
  email: `rate-${index}@example.invalid`,
  cnpj: makeCnpj(`${String(100000000000 + index).padStart(12, "0")}`),
  phone: `+55119999${String(90000 + index).slice(-5)}`,
});

test("rate-limit keys use a dedicated HMAC secret and never contain the source IP", () => {
  const secret = "synthetic-rate-limit-secret-that-is-long-enough";
  const ip = "203.0.113.42";
  const hashed = hashClientIp(ip, secret);
  assert.match(hashed, /^[0-9a-f]{64}$/);
  assert.equal(hashed.includes(ip), false);
  assert.notEqual(hashed, hashRateLimitKey({ secret, scope: "other", value: ip }));
  assert.throws(() => assertDedicatedRateLimitKeySecret(secret, [secret]), /reuse_forbidden/);
});

test("production HTTP configuration is explicit and rejects development origins", () => {
  const base = loadConfig({
    B2B_ENVIRONMENT: "production",
    B2B_ALLOWED_ORIGIN: "https://portal.example.invalid",
    B2B_TRUST_PROXY_HOPS: "1",
  });
  assert.doesNotThrow(() => assertWebHttpSecurityConfig(base));
  assert.throws(() => assertWebHttpSecurityConfig({ ...base, trustProxyConfigured: false }), /explicitly configured/);
  assert.throws(() => assertWebHttpSecurityConfig({
    ...base, allowedOrigins: ["http://localhost:3000"],
  }), /development_origin_forbidden/);
  assert.throws(() => loadConfig({
    B2B_ENVIRONMENT: "production",
    B2B_ALLOWED_ORIGIN: "https://portal.example.invalid/path",
    B2B_TRUST_PROXY_HOPS: "1",
  }), /allowed_origin_invalid/);
});

test("shared limiter is atomic under concurrent requests", async () => {
  const ctx = makeTestContext({ config: { sharedRateLimitMax: 3 } });
  const responses = await Promise.all(Array.from({ length: 12 }, (_, index) => post(ctx, uniquePayload(index + 1))));
  assert.equal(responses.filter((response) => response.status === 201).length, 3);
  assert.equal(responses.filter((response) => response.status === 429).length, 9);
  assert.equal(ctx.store.registrations.size, 3);
});

test("two application instances share the same limiter store", async () => {
  const store = new MemoryRegistrationStore({ clock: () => new Date("2030-01-01T00:00:00.000Z") });
  const config = { sharedRateLimitMax: 1, activeReservationsPerIpMax: 10 };
  const first = makeTestContext({ store, config });
  const second = makeTestContext({ store, config });
  assert.equal((await post(first, uniquePayload(21))).status, 201);
  const limited = await post(second, uniquePayload(22));
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error.code, "rate_limited");
  assert.equal(limited.headers.ratelimit, undefined);
  assert.equal(limited.headers["x-ratelimit-remaining"], undefined);
});

test("same idempotent request does not consume shared or identity quota twice", async () => {
  const ctx = makeTestContext({ config: { sharedRateLimitMax: 1, identityRateLimitMax: 1 } });
  const key = newKey();
  const first = await post(ctx, defaultPayload(), key);
  const second = await post(ctx, defaultPayload(), key);
  assert.equal(first.status, 201);
  assert.deepEqual(second.body, first.body);
  assert.equal(ctx.registryCalls, 1);
  assert.deepEqual([...ctx.store.rateLimitBuckets.values()].map((bucket) => bucket.hit_count), [1, 1, 1, 1]);
  assert.equal(ctx.store.registrationAdmissions.size, 1);
});

test("shared windows expire and bounded cleanup removes stale state", async () => {
  const ctx = makeTestContext({
    config: {
      sharedRateLimitWindowMs: 1000,
      sharedRateLimitMax: 1,
      identityRateLimitWindowMs: 1000,
      identityRateLimitMax: 1,
      rateLimitStateRetentionMs: 1000,
    },
  });
  assert.equal((await post(ctx, uniquePayload(31))).status, 201);
  ctx.setNow("2030-01-01T00:00:02.001Z");
  assert.equal((await post(ctx, uniquePayload(32))).status, 201);
  await ctx.store.cleanupRegistrationAbuseState({ now: new Date("2030-01-01T00:00:04.000Z") });
  assert.equal(ctx.store.rateLimitBuckets.size, 0);
  assert.equal(ctx.store.registrationAdmissions.size, 0);
});

test("repeated normalized identity is limited before another registry call", async () => {
  let registryCalls = 0;
  const registryClient = {
    async checkCnpj() {
      registryCalls += 1;
      throw new ExternalServiceError("registry", "registry_unavailable");
    },
  };
  const ctx = makeTestContext({ registryClient, config: { identityRateLimitMax: 1 } });
  assert.equal((await post(ctx, uniquePayload(41))).status, 503);
  const limited = await post(ctx, {
    ...uniquePayload(42),
    email: uniquePayload(41).email.toUpperCase(),
  });
  assert.equal(limited.status, 429);
  assert.equal(registryCalls, 1);
});

test("active unbound reservations are limited by IP and expired reservations release quota", async () => {
  const ctx = makeTestContext({ config: { activeReservationsPerIpMax: 1 } });
  assert.equal((await post(ctx, uniquePayload(51))).status, 201);
  assert.equal((await post(ctx, uniquePayload(52))).status, 429);
  assert.equal(ctx.registryCalls, 1);

  ctx.setNow("2030-01-01T00:31:00.000Z");
  assert.equal((await post(ctx, uniquePayload(53))).status, 201);
  assert.equal(ctx.store.registrations.size, 2);
  assert.equal([...ctx.store.registrations.values()].filter((registration) => registration.status === "expired").length, 1);
});

test("X-Forwarded-For spoofing does not change the client key when no proxy is trusted", async () => {
  const ctx = makeTestContext({ config: { rateLimitMax: 1, trustProxyHops: 0 } });
  await request(ctx.app).post("/v1/registrations")
    .set("X-Forwarded-For", "198.51.100.10").set("Idempotency-Key", newKey()).send({});
  const second = await request(ctx.app).post("/v1/registrations")
    .set("X-Forwarded-For", "198.51.100.11").set("Idempotency-Key", newKey()).send({});
  assert.equal(second.status, 429);
  assert.equal(ctx.lines.join("\n").includes("198.51.100"), false);
});

test("production CORS is exact and registration requires Origin", async () => {
  const production = {
    environment: "production",
    allowedOrigins: ["https://portal.example.invalid"],
  };
  assert.equal((await post(makeTestContext({ config: production }), defaultPayload())).status, 403);
  assert.equal((await post(makeTestContext({ config: production }), defaultPayload(), newKey(), {
    Origin: "https://evil.example.invalid",
  })).status, 403);
  assert.equal((await post(makeTestContext({ config: production }), defaultPayload(), newKey(), {
    Origin: "https://portal.example.invalid",
  })).status, 201);
});

test("localhost and shopifypreview origins are development-only", async () => {
  const development = makeTestContext({ config: { environment: "development", allowedOrigins: [] } });
  assert.equal((await post(development, {}, newKey(), { Origin: "http://localhost:9292" })).status, 422);
  assert.equal((await post(development, {}, newKey(), { Origin: "https://theme.shopifypreview.com" })).status, 422);

  const production = makeTestContext({ config: {
    environment: "production", allowedOrigins: ["https://portal.example.invalid"],
  } });
  assert.equal((await post(production, {}, newKey(), { Origin: "http://localhost:9292" })).status, 403);
  assert.equal((await post(production, {}, newKey(), { Origin: "https://theme.shopifypreview.com" })).status, 403);
});

test("JSON endpoints reject unexpected content types and oversized bodies", async () => {
  const ctx = makeTestContext({ config: { jsonBodyLimitBytes: 1024 } });
  const wrongType = await request(ctx.app).post("/v1/registrations")
    .set("Idempotency-Key", newKey()).type("text/plain").send(JSON.stringify(defaultPayload()));
  assert.equal(wrongType.status, 415);
  assert.equal(wrongType.body.error.code, "unsupported_media_type");

  const oversized = await request(ctx.app).post("/v1/registrations")
    .set("Idempotency-Key", newKey()).send({ ...defaultPayload(), padding: "x".repeat(2000) });
  assert.equal(oversized.status, 413);
  assert.equal(oversized.body.error.code, "payload_too_large");
});

test("webhook bypasses registration limiter and still validates raw-body HMAC", async () => {
  const ctx = makeTestContext({ config: { rateLimitMax: 1, sharedRateLimitMax: 1 } });
  const raw = JSON.stringify({ id: "synthetic-rate-webhook", email: "webhook@example.invalid" });
  const hmac = crypto.createHmac("sha256", ctx.config.shopifyWebhookSecret).update(raw).digest("base64");
  const send = (id) => request(ctx.app).post("/webhooks/shopify/customers-create")
    .set("Content-Type", "application/json")
    .set("X-Shopify-Hmac-Sha256", hmac)
    .set("X-Shopify-Webhook-Id", id)
    .send(raw);
  assert.equal((await send("rate-webhook-1")).status, 202);
  assert.equal((await send("rate-webhook-2")).status, 202);
  assert.equal((await request(ctx.app).get("/health")).status, 200);
  assert.equal((await request(ctx.app).get("/health")).status, 200);
});

test("public failures contain no stack, SQL, external details or PII", async () => {
  const store = new MemoryRegistrationStore();
  store.consumeRegistrationQuota = async () => {
    throw new Error("SELECT secret FROM customers WHERE email='private@example.invalid'");
  };
  const ctx = makeTestContext({ store });
  const response = await post(ctx, defaultPayload());
  assert.equal(response.status, 500);
  assert.deepEqual(response.body, {
    ok: false,
    error: { code: "internal_error", message: "Request could not be completed." },
  });
  const serialized = `${JSON.stringify(response.body)}\n${ctx.lines.join("\n")}`;
  assert.equal(serialized.includes("SELECT"), false);
  assert.equal(serialized.includes("private@example.invalid"), false);
  assert.equal(serialized.includes("stack"), false);
});

test("server timeout settings are explicit", () => {
  const server = {};
  configureHttpServerTimeouts(server, {
    headerTimeoutMs: 9000,
    httpRequestTimeoutMs: 12000,
    keepAliveTimeoutMs: 4000,
  });
  assert.deepEqual(server, { headersTimeout: 9000, requestTimeout: 12000, keepAliveTimeout: 4000 });
});
