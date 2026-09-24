import assert from "node:assert/strict";
import { test } from "node:test";
import request from "supertest";
import { DATA_DIGEST_VERSION, registrationRequestDigest } from "../src/data-digests.js";
import { ExternalServiceError } from "../src/errors.js";
import { defaultPayload, makeCnpj, makeTestContext, maskCnpj, newKey } from "./helpers.js";
import { decryptRegistrationOperationalPayload } from "../src/pii-crypto.js";

const postRegistration = (ctx, payload = defaultPayload(), key = newKey()) => request(ctx.app).post("/v1/registrations").set("Idempotency-Key", key).send(payload);

test("creates a reservation for new normalized fields", async () => {
  const ctx = makeTestContext();
  const response = await postRegistration(ctx);
  assert.equal(response.status, 201);
  assert.equal(response.body.status, "reserved");
  assert.match(response.body.registration_id, /^[0-9a-f-]{36}$/);
  assert.ok(response.body.registration_token);
  const stored = await ctx.store.getRegistration(response.body.registration_id);
  assert.equal(stored.email_normalized, null);
  assert.equal(stored.cnpj_normalized, null);
  assert.equal(stored.phone_e164, null);
  const encrypted = await ctx.store.getOperationalPayload(stored.id);
  assert.deepEqual(decryptRegistrationOperationalPayload({
    registrationId: stored.id, encrypted, keyring: ctx.piiKeyring,
  }), defaultPayload());
  assert.equal(stored.request_digest_version, DATA_DIGEST_VERSION);
  assert.equal(stored.request_digest, registrationRequestDigest({
    email: defaultPayload().email,
    cnpj: defaultPayload().cnpj,
    phone: defaultPayload().phone,
  }, ctx.config.dataDigestSecret));
});

test("accepts a masked valid CNPJ without truncation", async () => {
  const ctx = makeTestContext();
  const cnpj = makeCnpj("223456789012");
  const response = await postRegistration(ctx, defaultPayload({ cnpj: maskCnpj(cnpj) }));
  assert.equal(response.status, 201);
  const encrypted = await ctx.store.getOperationalPayload(response.body.registration_id);
  assert.equal(decryptRegistrationOperationalPayload({
    registrationId: response.body.registration_id, encrypted, keyring: ctx.piiKeyring,
  }).cnpj, cnpj);
});

for (const [name, payload, code] of [
  ["invalid CNPJ", defaultPayload({ cnpj: "00000000000000" }), "invalid_cnpj"],
  ["too many CNPJ digits", defaultPayload({ cnpj: `${makeCnpj()}9` }), "invalid_cnpj"],
  ["invalid phone", defaultPayload({ phone: "+550000" }), "invalid_phone"],
  ["too many phone digits", defaultPayload({ phone: "+551199999000199" }), "invalid_phone"],
  ["invalid email", defaultPayload({ email: "not-an-email" }), "invalid_email"],
  ["password field", { ...defaultPayload(), password: "must-not-be-accepted" }, "invalid_request"],
]) test(`rejects ${name}`, async () => {
  const ctx = makeTestContext();
  const response = await postRegistration(ctx, payload);
  assert.equal(response.status, 422);
  assert.equal(response.body.error.code, code);
  assert.equal(ctx.registryCalls, 0);
});

test("rejects inactive CNPJ and creates no reservation", async () => {
  const registryClient = { async checkCnpj() { return { found: true, active: false, status: "INATIVA" }; } };
  const ctx = makeTestContext({ registryClient });
  const response = await postRegistration(ctx);
  assert.equal(response.status, 422);
  assert.equal(response.body.error.code, "inactive_cnpj");
  assert.equal(ctx.store.registrations.size, 0);
});

test("returns registry_unavailable and does not reserve", async () => {
  let calls = 0;
  const registryClient = { async checkCnpj() { calls += 1; throw new ExternalServiceError("registry", "registry_unavailable"); } };
  const ctx = makeTestContext({ registryClient });
  const first = await postRegistration(ctx);
  const second = await postRegistration(ctx, defaultPayload(), newKey());
  assert.equal(first.status, 503);
  assert.equal(first.body.error.code, "registry_unavailable");
  assert.equal(second.status, 503);
  assert.equal(calls, 2);
  assert.equal(ctx.store.fiscalCache.size, 0);
  assert.equal(ctx.store.registrations.size, 0);
});

test("prechecks email, CNPJ and phone uniqueness without another registry call", async () => {
  const ctx = makeTestContext();
  const first = defaultPayload();
  assert.equal((await postRegistration(ctx, first)).status, 201);
  const cases = [
    [defaultPayload({ cnpj: makeCnpj("323456789012"), phone: "+5511999990002" }), "email_in_use"],
    [defaultPayload({ email: "outro@example.invalid", phone: "+5511999990003" }), "cnpj_in_use"],
    [defaultPayload({ email: "terceiro@example.invalid", cnpj: makeCnpj("423456789012") }), "phone_in_use"],
  ];
  for (const [payload, code] of cases) {
    const response = await postRegistration(ctx, payload);
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, code);
    assert.equal(ctx.registryCalls, 1);
  }
});

test("valid fiscal cache avoids a registry call", async () => {
  const ctx = makeTestContext();
  const cnpj = makeCnpj("333456789012");
  await ctx.store.setFiscalCache({
    cnpj, found: true, active: true, status: "ATIVA",
    checkedAt: ctx.clock(), expiresAt: new Date(ctx.clock().getTime() + 60_000),
  });
  const response = await postRegistration(ctx, defaultPayload({ cnpj }));
  assert.equal(response.status, 201);
  assert.equal(ctx.registryCalls, 0);
});

test("expired fiscal cache causes a new registry call", async () => {
  const ctx = makeTestContext();
  const cnpj = makeCnpj("343456789012");
  await ctx.store.setFiscalCache({
    cnpj, found: true, active: true, status: "ATIVA",
    checkedAt: new Date(ctx.clock().getTime() - 120_000),
    expiresAt: new Date(ctx.clock().getTime() - 60_000),
  });
  const response = await postRegistration(ctx, defaultPayload({ cnpj }));
  assert.equal(response.status, 201);
  assert.equal(ctx.registryCalls, 1);
});

test("normalizes alternate Brazilian phone formatting before uniqueness", async () => {
  const ctx = makeTestContext();
  await postRegistration(ctx, defaultPayload({ phone: "(11) 99999-0001" }));
  const response = await postRegistration(ctx, defaultPayload({ email: "outro@example.invalid", cnpj: makeCnpj("523456789012"), phone: "+55 11 99999-0001" }));
  assert.equal(response.status, 409);
  assert.equal(response.body.error.code, "phone_in_use");
});

test("same Idempotency-Key returns the same response without another registry call", async () => {
  const ctx = makeTestContext();
  const key = newKey();
  const first = await postRegistration(ctx, defaultPayload(), key);
  const second = await postRegistration(ctx, defaultPayload(), key);
  assert.deepEqual(second.body, first.body);
  assert.equal(ctx.registryCalls, 1);
});

test("registration status requires the opaque token and exposes no PII", async () => {
  const ctx = makeTestContext();
  const created = await postRegistration(ctx);
  const unauthorized = await request(ctx.app).get(`/v1/registrations/${created.body.registration_id}`);
  assert.equal(unauthorized.status, 401);
  const response = await request(ctx.app).get(`/v1/registrations/${created.body.registration_id}`)
    .set("Authorization", `Bearer ${created.body.registration_token}`);
  assert.equal(response.status, 200);
  assert.equal(response.body.status, "reserved");
  assert.equal("email" in response.body, false);
  assert.equal("cnpj" in response.body, false);
  assert.equal("phone" in response.body, false);
});

test("registration token is rejected at and after the exact expiration boundary", async () => {
  const ctx = makeTestContext({ config: { registrationTokenClockToleranceMs: 0 } });
  const created = await postRegistration(ctx);
  ctx.setNow(created.body.expires_at);
  const atBoundary = await request(ctx.app).get(`/v1/registrations/${created.body.registration_id}`)
    .set("Authorization", `Bearer ${created.body.registration_token}`);
  assert.equal(atBoundary.status, 401);
  assert.equal(atBoundary.body.error.code, "unauthorized");
  ctx.setNow(new Date(new Date(created.body.expires_at).getTime() + 1).toISOString());
  const expired = await request(ctx.app).get(`/v1/registrations/${created.body.registration_id}`)
    .set("Authorization", `Bearer ${created.body.registration_token}`);
  assert.equal(expired.status, 401);
  assert.deepEqual(expired.body, atBoundary.body);
});

test("registration token clock tolerance fails closed before expiration", async () => {
  const ctx = makeTestContext({ config: { registrationTokenClockToleranceMs: 1000 } });
  const created = await postRegistration(ctx);
  ctx.setNow(new Date(new Date(created.body.expires_at).getTime() - 999).toISOString());
  const response = await request(ctx.app).get(`/v1/registrations/${created.body.registration_id}`)
    .set("Authorization", `Bearer ${created.body.registration_token}`);
  assert.equal(response.status, 401);
});

test("registration token rejects invalid signature, another ID and tampered expiration generically", async () => {
  const ctx = makeTestContext();
  const first = await postRegistration(ctx);
  const second = await postRegistration(ctx, defaultPayload({
    email: "second-token@example.invalid",
    cnpj: makeCnpj("223456789012"),
    phone: "+5511999990002",
  }));
  const invalid = await request(ctx.app).get(`/v1/registrations/${first.body.registration_id}`)
    .set("Authorization", "Bearer invalid-signature");
  const otherId = await request(ctx.app).get(`/v1/registrations/${second.body.registration_id}`)
    .set("Authorization", `Bearer ${first.body.registration_token}`);
  const stored = ctx.store.registrations.get(first.body.registration_id);
  stored.expires_at = new Date(new Date(stored.expires_at).getTime() + 60_000);
  const tamperedExpiration = await request(ctx.app).get(`/v1/registrations/${first.body.registration_id}`)
    .set("Authorization", `Bearer ${first.body.registration_token}`);
  for (const response of [invalid, otherId, tamperedExpiration]) {
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "unauthorized");
  }
});

test("registration token secret rotation invalidates the old token and missing IDs are indistinguishable", async () => {
  const ctx = makeTestContext();
  const created = await postRegistration(ctx);
  ctx.config.registrationTokenSecret = "rotated-registration-token-secret-not-production";
  const rotated = await request(ctx.app).get(`/v1/registrations/${created.body.registration_id}`)
    .set("Authorization", `Bearer ${created.body.registration_token}`);
  const missing = await request(ctx.app).get(`/v1/registrations/${newKey()}`)
    .set("Authorization", `Bearer ${created.body.registration_token}`);
  assert.equal(rotated.status, 401);
  assert.deepEqual(missing.body, rotated.body);
  assert.equal(missing.status, rotated.status);
});

test("same Idempotency-Key with different payload conflicts", async () => {
  const ctx = makeTestContext();
  const key = newKey();
  await postRegistration(ctx, defaultPayload(), key);
  const response = await postRegistration(ctx, defaultPayload({ email: "other@example.invalid" }), key);
  assert.equal(response.status, 409);
  assert.equal(response.body.error.code, "idempotency_conflict");
});

test("expired unbound reservation releases all unique values", async () => {
  const ctx = makeTestContext();
  const first = await postRegistration(ctx);
  ctx.setNow("2030-01-01T00:31:00.000Z");
  const second = await postRegistration(ctx, defaultPayload(), newKey());
  assert.equal(second.status, 201);
  assert.notEqual(second.body.registration_id, first.body.registration_id);
  assert.equal(ctx.store.registrations.size, 2);
  const released = [...ctx.store.registrationIdentityClaims.values()]
    .filter((claim) => claim.registration_id === first.body.registration_id);
  assert.ok(released.every((claim) => claim.claim_state === "released"));
  assert.equal(ctx.registryCalls, 1);
});

test("concurrent reservations allow only one CNPJ and one phone", async () => {
  const ctx = makeTestContext();
  const sharedCnpj = makeCnpj("623456789012");
  const cnpjResults = await Promise.all([
    postRegistration(ctx, defaultPayload({ email: "a@example.invalid", cnpj: sharedCnpj, phone: "+5511999990011" })),
    postRegistration(ctx, defaultPayload({ email: "b@example.invalid", cnpj: sharedCnpj, phone: "+5511999990012" })),
  ]);
  assert.deepEqual(cnpjResults.map((r) => r.status).sort(), [201, 409]);
  assert.equal(cnpjResults.find((r) => r.status === 409).body.error.code, "cnpj_in_use");

  const sharedPhone = "+5511999990013";
  const phoneResults = await Promise.all([
    postRegistration(ctx, defaultPayload({ email: "c@example.invalid", cnpj: makeCnpj("723456789012"), phone: sharedPhone })),
    postRegistration(ctx, defaultPayload({ email: "d@example.invalid", cnpj: makeCnpj("823456789012"), phone: sharedPhone })),
  ]);
  assert.deepEqual(phoneResults.map((r) => r.status).sort(), [201, 409]);
  assert.equal(phoneResults.find((r) => r.status === 409).body.error.code, "phone_in_use");
});

test("rate limiter uses the public rate_limited contract", async () => {
  const ctx = makeTestContext({ config: { rateLimitMax: 1 } });
  await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey()).send({});
  const response = await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey()).send({});
  assert.equal(response.status, 429);
  assert.equal(response.body.error.code, "rate_limited");
});
