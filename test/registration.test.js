import assert from "node:assert/strict";
import { test } from "node:test";
import request from "supertest";
import { ExternalServiceError } from "../src/errors.js";
import { defaultPayload, makeCnpj, makeTestContext, maskCnpj, newKey } from "./helpers.js";

const postRegistration = (ctx, payload = defaultPayload(), key = newKey()) => request(ctx.app).post("/v1/registrations").set("Idempotency-Key", key).send(payload);

test("creates a reservation for new normalized fields", async () => {
  const ctx = makeTestContext();
  const response = await postRegistration(ctx);
  assert.equal(response.status, 201);
  assert.equal(response.body.status, "reserved");
  assert.match(response.body.registration_id, /^[0-9a-f-]{36}$/);
  assert.ok(response.body.registration_token);
  const stored = await ctx.store.getRegistration(response.body.registration_id);
  assert.equal(stored.email_normalized, "empresa@example.invalid");
  assert.equal(stored.phone_e164, "+5511999990001");
});

test("accepts a masked valid CNPJ without truncation", async () => {
  const ctx = makeTestContext();
  const cnpj = makeCnpj("223456789012");
  const response = await postRegistration(ctx, defaultPayload({ cnpj: maskCnpj(cnpj) }));
  assert.equal(response.status, 201);
  assert.equal((await ctx.store.getRegistration(response.body.registration_id)).cnpj_normalized, cnpj);
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
  const registryClient = { async checkCnpj() { throw new ExternalServiceError("registry", "registry_unavailable"); } };
  const ctx = makeTestContext({ registryClient });
  const response = await postRegistration(ctx);
  assert.equal(response.status, 503);
  assert.equal(response.body.error.code, "registry_unavailable");
  assert.equal(ctx.store.registrations.size, 0);
});

test("enforces email, CNPJ and phone uniqueness", async () => {
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
  }
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
  ctx.setNow("2030-01-01T01:00:00.000Z");
  const second = await postRegistration(ctx, defaultPayload(), newKey());
  assert.equal(second.status, 201);
  assert.notEqual(second.body.registration_id, first.body.registration_id);
  assert.equal(ctx.store.registrations.size, 1);
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
