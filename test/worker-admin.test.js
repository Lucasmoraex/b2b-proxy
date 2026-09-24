import assert from "node:assert/strict";
import { test } from "node:test";
import request from "supertest";
import { OutboxWorker } from "../src/worker.js";
import { defaultPayload, makeTestContext, newKey } from "./helpers.js";
import { buildRegistrationIdentityClaims } from "../src/registration-identities.js";

function shopifyMock(overrides = {}) {
  const calls = [];
  return {
    calls,
    async updatePhone(id, phone) { calls.push(["phone", id, phone]); },
    async setMetafields(id, fields) { calls.push(["metafields", id, fields]); },
    async addTags(id, tags) { calls.push(["addTags", id, tags]); },
    async removeTags(id, tags) { calls.push(["removeTags", id, tags]); },
    async getCustomerState(id) { calls.push(["get", id]); return { id }; },
    ...overrides,
  };
}

async function boundRegistration(ctx, customerId = "synthetic-customer-1") {
  const response = await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey()).send(defaultPayload());
  const registration = await ctx.store.getRegistration(response.body.registration_id);
  const [emailClaim] = buildRegistrationIdentityClaims({
    ...defaultPayload(), secret: ctx.config.dataDigestSecret,
  });
  await ctx.store.associateWebhook({
    eventId: newKey(), topic: "customers/create", payloadDigest: "a".repeat(64), payloadDigestVersion: "hmac-sha256-v1",
    email: defaultPayload().email, emailClaim, customerId, now: ctx.clock(),
  });
  return ctx.store.getRegistration(registration.id);
}

test("worker synchronizes by customer_id and keeps account pending review", async () => {
  const ctx = makeTestContext();
  const registration = await boundRegistration(ctx);
  const shopify = shopifyMock();
  const worker = new OutboxWorker({ store: ctx.store, shopifyClient: shopify, clock: ctx.clock, logger: ctx.logger, piiKeyring: ctx.piiKeyring, autoApprove: false });
  assert.equal(await worker.runOnce(), true);
  const stored = await ctx.store.getRegistration(registration.id);
  assert.equal(stored.status, "pending_review");
  assert.ok(stored.sync_completed_at);
  assert.ok(shopify.calls.every((call) => call[1] === "synthetic-customer-1"));
  assert.ok(shopify.calls.some((call) => call[0] === "phone" && call[2] === defaultPayload().phone));
  assert.ok(shopify.calls.some((call) => call[0] === "metafields"
    && call[2].some((field) => field.key === "cnpj" && field.value === defaultPayload().cnpj)));
  assert.equal(shopify.calls.some((call) => call[0] === "addTags" && call[2].includes("b2b-approved")), false);
});

test("Shopify failure schedules exponential retry with sanitized error", async () => {
  const ctx = makeTestContext();
  await boundRegistration(ctx);
  const shopify = shopifyMock({ async updatePhone() { throw Object.assign(new Error("private-person@example.invalid"), { code: "shopify_unavailable" }); } });
  const worker = new OutboxWorker({ store: ctx.store, shopifyClient: shopify, clock: ctx.clock, logger: ctx.logger, piiKeyring: ctx.piiKeyring, maxAttempts: 3 });
  await worker.runOnce();
  const item = [...ctx.store.outbox.values()][0];
  assert.equal(item.attempts, 1);
  assert.equal(item.processed_at, null);
  assert.equal(item.last_error, null);
  assert.equal(item.error_code, "shopify_unavailable");
  assert.equal(item.error_category, "shopify");
  assert.equal(JSON.stringify(item).includes("private-person"), false);
  assert.ok(new Date(item.next_attempt_at) > ctx.clock());
});

test("partial metafield/tag failure converges on retry", async () => {
  const ctx = makeTestContext();
  const registration = await boundRegistration(ctx);
  let addAttempts = 0;
  const shopify = shopifyMock({
    async addTags(id, tags) {
      this.calls.push(["addTags", id, tags]);
      addAttempts += 1;
      if (addAttempts === 1) throw Object.assign(new Error("temporary"), { code: "shopify_unavailable" });
    },
  });
  const worker = new OutboxWorker({ store: ctx.store, shopifyClient: shopify, clock: ctx.clock, logger: ctx.logger, piiKeyring: ctx.piiKeyring });
  await worker.runOnce();
  assert.equal((await ctx.store.getRegistration(registration.id)).status, "pending_validation");
  ctx.setNow("2030-01-01T00:00:03.000Z");
  await worker.runOnce();
  assert.equal((await ctx.store.getRegistration(registration.id)).status, "pending_review");
  assert.equal(addAttempts, 2);
  assert.equal(shopify.calls.filter((call) => call[0] === "metafields").length, 2);
});

test("approval fails without CNPJ and while registration is pending", async () => {
  const ctx = makeTestContext();
  const pending = await boundRegistration(ctx);
  const pendingResponse = await request(ctx.app).post("/admin/approve")
    .set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: pending.id });
  assert.equal(pendingResponse.status, 409);
  assert.equal(pendingResponse.body.error.code, "registration_not_ready");

  const internal = ctx.store.registrations.get(pending.id);
  internal.cnpj_normalized = null;
  for (const claim of ctx.store.registrationIdentityClaims.values()) {
    if (claim.registration_id === pending.id && claim.identity_type === "cnpj") {
      claim.claim_state = "released";
      claim.released_at = ctx.clock();
    }
  }
  internal.status = "pending_review";
  internal.sync_completed_at = ctx.clock();
  const noCnpj = await request(ctx.app).post("/admin/approve")
    .set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: pending.id });
  assert.equal(noCnpj.status, 409);
  assert.equal(noCnpj.body.error.code, "missing_cnpj");
});

test("valid approval converges metafield and tag idempotently", async () => {
  const ctx = makeTestContext();
  const registration = await boundRegistration(ctx);
  const shopify = shopifyMock();
  const worker = new OutboxWorker({ store: ctx.store, shopifyClient: shopify, clock: ctx.clock, logger: ctx.logger, piiKeyring: ctx.piiKeyring });
  await worker.runOnce();
  const queued = await request(ctx.app).post("/admin/approve")
    .set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: registration.id });
  assert.equal(queued.status, 202);
  await worker.runOnce();
  assert.equal((await ctx.store.getRegistration(registration.id)).status, "approved");
  assert.ok(shopify.calls.some((call) => call[0] === "addTags" && call[2].includes("b2b-approved")));
  const again = await request(ctx.app).post("/admin/approve")
    .set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: registration.id });
  assert.equal(again.status, 200);
  assert.equal(again.body.queued, false);
});

test("rejection removes b2b-approved and is idempotent", async () => {
  const ctx = makeTestContext();
  const registration = await boundRegistration(ctx);
  const shopify = shopifyMock();
  const worker = new OutboxWorker({ store: ctx.store, shopifyClient: shopify, clock: ctx.clock, logger: ctx.logger, piiKeyring: ctx.piiKeyring });
  await worker.runOnce();
  await request(ctx.app).post("/admin/reject").set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ shopify_customer_id: registration.shopify_customer_id });
  await worker.runOnce();
  assert.equal((await ctx.store.getRegistration(registration.id)).status, "rejected");
  assert.ok(shopify.calls.some((call) => call[0] === "removeTags" && call[2].includes("b2b-approved")));
  const again = await request(ctx.app).post("/admin/reject").set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: registration.id });
  assert.equal(again.status, 200);
});

test("reconciliation is queued once and uses bound customer id", async () => {
  const ctx = makeTestContext();
  const registration = await boundRegistration(ctx);
  const shopify = shopifyMock();
  const worker = new OutboxWorker({ store: ctx.store, shopifyClient: shopify, clock: ctx.clock, logger: ctx.logger, piiKeyring: ctx.piiKeyring });
  await worker.runOnce();
  await request(ctx.app).post("/admin/reconcile").set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: registration.id });
  await request(ctx.app).post("/admin/reconcile").set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: registration.id });
  await worker.runOnce();
  assert.ok(shopify.calls.some((call) => call[0] === "get" && call[1] === registration.shopify_customer_id));
});
