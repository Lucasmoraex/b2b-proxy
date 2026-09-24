import assert from "node:assert/strict";
import { test } from "node:test";
import request from "supertest";
import {
  createPiiEncryptionKeyring,
  decryptRegistrationOperationalPayload,
  encryptRegistrationOperationalPayload,
} from "../src/pii-crypto.js";
import { buildRegistrationIdentityClaims } from "../src/registration-identities.js";
import { RetentionService } from "../src/retention.js";
import { OutboxWorker } from "../src/worker.js";
import { defaultPayload, makeCnpj, makeTestContext, newKey } from "./helpers.js";

const retentionConfig = (overrides = {}) => ({
  mode: "execute",
  enabled: true,
  confirmation: "EXECUTE_B2B_RETENTION",
  environment: "test",
  allowProduction: false,
  expiredUnlinkedMs: 24 * 60 * 60 * 1000,
  syncedPayloadMs: 7 * 24 * 60 * 60 * 1000,
  failedUnlinkedMs: 30 * 24 * 60 * 60 * 1000,
  operationalEventsMs: 30 * 24 * 60 * 60 * 1000,
  batchSize: 200,
  ...overrides,
});

const post = (ctx, payload = defaultPayload(), key = newKey()) => request(ctx.app)
  .post("/v1/registrations")
  .set("Idempotency-Key", key)
  .send(payload);

const bind = async (ctx, registrationId, payload = defaultPayload(), customerId = `synthetic-customer-${registrationId}`) => {
  const [emailClaim] = buildRegistrationIdentityClaims({ ...payload, secret: ctx.config.dataDigestSecret });
  return ctx.store.associateWebhook({
    eventId: newKey(),
    topic: "customers/create",
    payloadDigest: "a".repeat(64),
    payloadDigestVersion: "hmac-sha256-v1",
    email: payload.email,
    emailClaim,
    customerId,
    now: ctx.clock(),
  });
};

const shopifyMock = () => ({
  async updatePhone() {}, async setMetafields() {}, async addTags() {}, async removeTags() {},
  async getCustomerState(id) { return { id }; },
});

const sync = async (ctx) => new OutboxWorker({
  store: ctx.store,
  shopifyClient: shopifyMock(),
  clock: ctx.clock,
  logger: ctx.logger,
  piiKeyring: ctx.piiKeyring,
  syncedPayloadRetentionMs: retentionConfig().syncedPayloadMs,
}).runOnce();

test("AES-256-GCM round-trips with AAD and rejects tampering, missing and incorrect keys", () => {
  const keys = JSON.stringify({
    v1: Buffer.from("0123456789abcdef0123456789abcdef").toString("base64"),
  });
  const keyring = createPiiEncryptionKeyring({ activeVersion: "v1", serializedKeys: keys });
  const registrationId = newKey();
  const payload = defaultPayload();
  const encrypted = encryptRegistrationOperationalPayload({ registrationId, payload, keyring });
  assert.deepEqual(decryptRegistrationOperationalPayload({ registrationId, encrypted, keyring }), payload);

  const tampered = { ...encrypted, authTag: Buffer.from(encrypted.authTag) };
  tampered.authTag[0] ^= 1;
  assert.throws(() => decryptRegistrationOperationalPayload({ registrationId, encrypted: tampered, keyring }), /pii_payload_authentication_failed/);

  const wrong = createPiiEncryptionKeyring({
    activeVersion: "v1",
    serializedKeys: JSON.stringify({ v1: Buffer.from("abcdef0123456789abcdef0123456789").toString("base64") }),
  });
  assert.throws(() => decryptRegistrationOperationalPayload({ registrationId, encrypted, keyring: wrong }), /pii_payload_authentication_failed/);
  assert.throws(() => decryptRegistrationOperationalPayload({
    registrationId,
    encrypted: { ...encrypted, encryptionKeyVersion: "missing" },
    keyring,
  }), /pii_encryption_key_unavailable/);
  assert.throws(() => createPiiEncryptionKeyring({ activeVersion: "v1", serializedKeys: "{}" }), /pii_encryption_keys_invalid/);
});

test("PII keyring supports explicit key rotation and rejects reuse of another application secret", () => {
  const v1 = Buffer.from("0123456789abcdef0123456789abcdef");
  const v2 = Buffer.from("abcdef0123456789abcdef0123456789");
  const serializedKeys = JSON.stringify({ v1: v1.toString("base64"), v2: v2.toString("base64") });
  const registrationId = newKey();
  const oldKeyring = createPiiEncryptionKeyring({ activeVersion: "v1", serializedKeys });
  const encrypted = encryptRegistrationOperationalPayload({
    registrationId, payload: defaultPayload(), keyring: oldKeyring,
  });
  const rotated = createPiiEncryptionKeyring({ activeVersion: "v2", serializedKeys });
  assert.deepEqual(decryptRegistrationOperationalPayload({ registrationId, encrypted, keyring: rotated }), defaultPayload());
  assert.throws(() => createPiiEncryptionKeyring({
    activeVersion: "v1",
    serializedKeys: JSON.stringify({ v1: v1.toString("base64") }),
    otherSecrets: [v1.toString("utf8")],
  }), /pii_encryption_key_reuse_forbidden/);
});

test("new registration stores no plaintext PII in registration, claims or operational payload", async () => {
  const ctx = makeTestContext();
  const response = await post(ctx);
  assert.equal(response.status, 201);
  const registration = ctx.store.registrations.get(response.body.registration_id);
  assert.equal(registration.email_normalized, null);
  assert.equal(registration.cnpj_normalized, null);
  assert.equal(registration.phone_e164, null);
  const persisted = JSON.stringify({
    registration,
    claims: [...ctx.store.registrationIdentityClaims.values()],
    payload: ctx.store.operationalPayloads.get(registration.id),
  });
  for (const value of Object.values(defaultPayload())) assert.equal(persisted.includes(value), false);
  assert.equal([...ctx.store.registrationIdentityClaims.values()].filter((claim) => claim.registration_id === registration.id).length, 3);
});

test("blind indexes block normalized duplicates before another registry lookup", async () => {
  const ctx = makeTestContext();
  assert.equal((await post(ctx)).status, 201);
  const cases = [
    [defaultPayload({ cnpj: makeCnpj("223456789012"), phone: "+5511999991002" }), "email_in_use"],
    [defaultPayload({ email: "cnpj-new@example.invalid", phone: "+5511999991003" }), "cnpj_in_use"],
    [defaultPayload({ email: "phone-new@example.invalid", cnpj: makeCnpj("323456789012") }), "phone_in_use"],
  ];
  for (const [payload, code] of cases) {
    const response = await post(ctx, payload);
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, code);
  }
  assert.equal(ctx.registryCalls, 1);
});

test("linked claims remain blocking after payload purge and idempotency still resolves", async () => {
  const ctx = makeTestContext();
  const key = newKey();
  const created = await post(ctx, defaultPayload(), key);
  await bind(ctx, created.body.registration_id);
  await sync(ctx);
  ctx.setNow("2030-01-09T00:00:01.000Z");
  const service = new RetentionService({ store: ctx.store, clock: ctx.clock, logger: ctx.logger });
  const summary = await service.run(retentionConfig());
  assert.equal(summary.purged_payloads, 1);
  assert.ok(ctx.store.operationalPayloads.get(created.body.registration_id).purged_at);
  const claims = [...ctx.store.registrationIdentityClaims.values()].filter((claim) => claim.registration_id === created.body.registration_id);
  assert.equal(claims.find((claim) => claim.identity_type === "cnpj").claim_state, "tombstoned");
  assert.equal(claims.find((claim) => claim.identity_type === "email").claim_state, "active");
  assert.equal(claims.find((claim) => claim.identity_type === "phone").claim_state, "active");

  const idempotent = await post(ctx, defaultPayload(), key);
  assert.equal(idempotent.status, 201);
  assert.equal(idempotent.body.registration_id, created.body.registration_id);
  for (const [payload, code] of [
    [defaultPayload({ email: "new-cnpj@example.invalid", phone: "+5511999992001" }), "cnpj_in_use"],
    [defaultPayload({ cnpj: makeCnpj("423456789012"), phone: "+5511999992002" }), "email_in_use"],
    [defaultPayload({ email: "new-phone@example.invalid", cnpj: makeCnpj("523456789012") }), "phone_in_use"],
  ]) {
    const response = await post(ctx, payload);
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, code);
  }
});

test("expired unlinked reservation releases all claims and linked failed or rejected registrations do not", async () => {
  const expiredCtx = makeTestContext();
  const expired = await post(expiredCtx);
  expiredCtx.setNow("2030-01-03T00:31:00.000Z");
  await new RetentionService({ store: expiredCtx.store, clock: expiredCtx.clock, logger: expiredCtx.logger })
    .run(retentionConfig());
  const released = [...expiredCtx.store.registrationIdentityClaims.values()]
    .filter((claim) => claim.registration_id === expired.body.registration_id);
  assert.ok(released.every((claim) => claim.claim_state === "released"));
  assert.equal((await post(expiredCtx, defaultPayload(), newKey())).status, 201);

  for (const status of ["failed", "rejected"]) {
    const ctx = makeTestContext();
    const created = await post(ctx);
    await bind(ctx, created.body.registration_id, defaultPayload(), `synthetic-${status}`);
    ctx.store.registrations.get(created.body.registration_id).status = status;
    ctx.setNow("2031-03-01T00:00:00.000Z");
    await new RetentionService({ store: ctx.store, clock: ctx.clock, logger: ctx.logger }).run(retentionConfig());
    const claims = [...ctx.store.registrationIdentityClaims.values()]
      .filter((claim) => claim.registration_id === created.body.registration_id);
    assert.ok(claims.every((claim) => claim.claim_state !== "released"));
  }
});

test("failed unlinked registration uses the longer failure retention window", async () => {
  const ctx = makeTestContext();
  const created = await post(ctx);
  const registration = ctx.store.registrations.get(created.body.registration_id);
  registration.status = "failed";
  registration.updated_at = ctx.clock();
  const service = new RetentionService({ store: ctx.store, clock: ctx.clock, logger: ctx.logger });

  ctx.setNow("2030-01-03T00:31:00.000Z");
  assert.equal((await service.run(retentionConfig())).released_registrations, 0);
  assert.ok([...ctx.store.registrationIdentityClaims.values()]
    .filter((claim) => claim.registration_id === registration.id)
    .every((claim) => claim.claim_state === "reserved"));

  ctx.setNow("2030-02-01T00:00:01.000Z");
  assert.equal((await service.run(retentionConfig())).released_registrations, 1);
  assert.ok([...ctx.store.registrationIdentityClaims.values()]
    .filter((claim) => claim.registration_id === registration.id)
    .every((claim) => claim.claim_state === "released"));
});

test("retention execution is disabled and production-refused unless explicitly unlocked", async () => {
  const store = {
    writes: 0,
    async reportRetentionCandidates() { return {}; },
    async applyRetentionBatch() { this.writes += 1; return {}; },
  };
  const service = new RetentionService({ store });
  await assert.rejects(service.run(retentionConfig({ enabled: false })), /retention_disabled/);
  await assert.rejects(service.run(retentionConfig({ confirmation: "wrong" })), /retention_confirmation_required/);
  await assert.rejects(service.run(retentionConfig({ environment: "production" })), /retention_production_refused/);
  assert.equal(store.writes, 0);
});

test("retention report-only, pending outbox and legal hold never purge data", async () => {
  const ctx = makeTestContext();
  const created = await post(ctx);
  await bind(ctx, created.body.registration_id);
  const registration = ctx.store.registrations.get(created.body.registration_id);
  registration.sync_completed_at = ctx.clock();
  ctx.store.operationalPayloads.get(created.body.registration_id).needed_until = new Date("2029-01-01T00:00:00.000Z");
  ctx.setNow("2031-01-01T00:00:00.000Z");
  const service = new RetentionService({ store: ctx.store, clock: ctx.clock, logger: ctx.logger });
  const before = JSON.stringify([...ctx.store.operationalPayloads.entries()]);
  const report = await service.run(retentionConfig({ mode: "report-only", enabled: false }));
  assert.equal(report.purged_payloads, 0);
  assert.equal(JSON.stringify([...ctx.store.operationalPayloads.entries()]), before);
  assert.equal((await service.run(retentionConfig())).purged_payloads, 0);

  ctx.store.outbox.clear();
  registration.retention_hold_until = new Date("2032-01-01T00:00:00.000Z");
  assert.equal((await service.run(retentionConfig())).purged_payloads, 0);
  assert.equal(ctx.store.operationalPayloads.get(created.body.registration_id).purged_at, null);
});

test("concurrent retention batches are bounded and never expose PII in logs", async () => {
  const ctx = makeTestContext();
  const payloads = [
    defaultPayload(),
    defaultPayload({ email: "second-retention@example.invalid", cnpj: makeCnpj("623456789012"), phone: "+5511999993002" }),
  ];
  for (const [index, payload] of payloads.entries()) {
    const created = await post(ctx, payload);
    await bind(ctx, created.body.registration_id, payload, `synthetic-retention-${index}`);
  }
  await sync(ctx);
  await sync(ctx);
  ctx.setNow("2030-01-09T00:00:01.000Z");
  const service = new RetentionService({ store: ctx.store, clock: ctx.clock, logger: ctx.logger });
  const results = await Promise.all([
    service.run(retentionConfig({ batchSize: 1 })),
    service.run(retentionConfig({ batchSize: 1 })),
  ]);
  assert.equal(results.reduce((total, result) => total + result.purged_payloads, 0), 2);
  const output = ctx.lines.join("\n");
  for (const payload of payloads) for (const value of Object.values(payload)) assert.equal(output.includes(value), false);
});

test("purged payload makes reconciliation fail structurally without scheduling retries", async () => {
  const ctx = makeTestContext();
  const created = await post(ctx);
  await bind(ctx, created.body.registration_id);
  await sync(ctx);
  ctx.setNow("2030-01-09T00:00:01.000Z");
  await new RetentionService({ store: ctx.store, clock: ctx.clock, logger: ctx.logger }).run(retentionConfig());
  await assert.rejects(ctx.store.enqueueReconciliation(created.body.registration_id), (error) => (
    error.code === "payload_purged" && error.status === 409
  ));
  assert.equal([...ctx.store.outbox.values()].filter((item) => !item.processed_at).length, 0);
});
