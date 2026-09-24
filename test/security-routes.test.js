import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import request from "supertest";
import { ReceitaWsClient } from "../src/clients/receita-ws.js";
import { ShopifyGraphqlClient } from "../src/clients/shopify-graphql.js";
import { DATA_DIGEST_VERSION, webhookPayloadDigest } from "../src/data-digests.js";
import { defaultPayload, makeTestContext, newKey } from "./helpers.js";

const abortingFetch = async (_url, options) => new Promise((_resolve, reject) => {
  options.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
});

test("ReceitaWS classifies INATIVA as inactive", async () => {
  const client = new ReceitaWsClient({
    fetchImpl: async () => ({ ok: true, async json() { return { nome: "Synthetic Test", situacao_cadastral: "INATIVA" }; } }),
    baseUrl: "https://registry.example.invalid", timeoutMs: 50,
  });
  const result = await client.checkCnpj(defaultPayload().cnpj);
  assert.equal(result.found, true);
  assert.equal(result.active, false);
});

test("ReceitaWS timeout is sanitized as registry_unavailable", async () => {
  const client = new ReceitaWsClient({ fetchImpl: abortingFetch, baseUrl: "https://registry.example.invalid", timeoutMs: 5 });
  await assert.rejects(client.checkCnpj(defaultPayload().cnpj), (error) => error.code === "registry_unavailable" && error.status === 503);
});

test("ReceitaWS accepts only bearer authentication or explicit tokenless mode", async () => {
  assert.throws(() => new ReceitaWsClient({
    fetchImpl: async () => {}, baseUrl: "https://registry.example.invalid", token: "synthetic", tokenMode: "query",
  }), /registry_token_mode_invalid/);
  assert.throws(() => new ReceitaWsClient({
    fetchImpl: async () => {}, baseUrl: "https://registry.example.invalid", token: "synthetic", tokenMode: "none",
  }), /registry_token_forbidden_in_none_mode/);
  let observed;
  const bearer = new ReceitaWsClient({
    fetchImpl: async (url, options) => {
      observed = { url, authorization: options.headers.Authorization };
      return { ok: true, async json() { return { nome: "Synthetic", situacao: "ATIVA" }; } };
    },
    baseUrl: "https://registry.example.invalid",
    token: "synthetic-bearer-token",
    tokenMode: "bearer",
  });
  await bearer.checkCnpj(defaultPayload().cnpj);
  assert.equal(observed.url.includes("token="), false);
  assert.equal(observed.authorization, "Bearer synthetic-bearer-token");
});

test("Shopify timeout is sanitized as shopify_unavailable", async () => {
  const client = new ShopifyGraphqlClient({ fetchImpl: abortingFetch, shop: "shop.example.invalid", token: "fake", apiVersion: "2026-07", timeoutMs: 5 });
  await assert.rejects(client.getCustomerState("123"), (error) => error.code === "shopify_unavailable" && error.status === 503);
});

test("Shopify email search rejects a different returned email", async () => {
  const client = new ShopifyGraphqlClient({
    fetchImpl: async () => ({ ok: true, async json() { return { data: { customers: { nodes: [{ id: "gid://shopify/Customer/1", email: "different@example.invalid" }] } } }; } }),
    shop: "shop.example.invalid", token: "fake", apiVersion: "2026-07", timeoutMs: 50,
  });
  assert.equal(await client.findCustomerByExactEmail("expected@example.invalid"), null);
});

test("Shopify client credentials are exchanged once and cached", async () => {
  let tokenCalls = 0; let graphqlCalls = 0;
  const fetchImpl = async (url) => {
    if (url.endsWith("/admin/oauth/access_token")) {
      tokenCalls += 1;
      return { ok: true, async json() { return { access_token: "synthetic-short-lived-token", expires_in: 86399 }; } };
    }
    graphqlCalls += 1;
    return { ok: true, async json() { return { data: { customer: { id: "gid://shopify/Customer/synthetic" } } }; } };
  };
  const client = new ShopifyGraphqlClient({
    fetchImpl, shop: "development-shop", clientId: "synthetic-id", clientSecret: "synthetic-secret",
    apiVersion: "2026-07", timeoutMs: 50, clock: () => new Date("2030-01-01T00:00:00Z"),
  });
  await client.getCustomerState("synthetic");
  await client.getCustomerState("synthetic");
  assert.equal(tokenCalls, 1);
  assert.equal(graphqlCalls, 2);
});

test("administrative routes require a header secret and reject query secrets", async () => {
  const ctx = makeTestContext();
  const without = await request(ctx.app).post("/admin/approve").send({ registration_id: newKey() });
  assert.equal(without.status, 401);
  const queryOnly = await request(ctx.app).post(`/admin/approve?secret=${encodeURIComponent(ctx.config.adminSecret)}`).send({ registration_id: newKey() });
  assert.equal(queryOnly.status, 400);
  assert.equal(queryOnly.body.error.code, "invalid_request");
  const queryWithHeader = await request(ctx.app)
    .post(`/admin/approve?secret=${encodeURIComponent(ctx.config.adminSecret)}`)
    .set("X-B2B-Admin-Secret", ctx.config.adminSecret)
    .send({ registration_id: newKey() });
  assert.equal(queryWithHeader.status, 400);
  const withHeader = await request(ctx.app).post("/admin/approve").set("X-B2B-Admin-Secret", ctx.config.adminSecret).send({ registration_id: newKey() });
  assert.equal(withHeader.status, 404);
});

test("administrative GET variants do not exist", async () => {
  const ctx = makeTestContext();
  assert.equal((await request(ctx.app).get("/admin/approve").set("X-B2B-Admin-Secret", ctx.config.adminSecret)).status, 404);
  assert.equal((await request(ctx.app).get("/admin/reject").set("X-B2B-Admin-Secret", ctx.config.adminSecret)).status, 404);
});

test("legacy mutation and login endpoints are blocked by default", async () => {
  let mutationCalls = 0;
  const ctx = makeTestContext({ legacyMutationHandler: { async register() { mutationCalls += 1; } } });
  assert.equal((await request(ctx.app).post("/register-cnpj").send(defaultPayload())).status, 410);
  assert.equal((await request(ctx.app).post("/validate-cnpj").send({ cnpj: defaultPayload().cnpj })).status, 410);
  assert.equal((await request(ctx.app).get("/validate-login?email=private@example.invalid&cnpj=00000000000000")).status, 410);
  assert.equal(mutationCalls, 0);
});

test("even enabled legacy mutation requires admin header", async () => {
  let mutationCalls = 0;
  const ctx = makeTestContext({ config: { enableLegacyMutations: true }, legacyMutationHandler: { async register() { mutationCalls += 1; return { ok: true }; } } });
  assert.equal((await request(ctx.app).post("/register-cnpj").send(defaultPayload())).status, 401);
  assert.equal(mutationCalls, 0);
  assert.equal((await request(ctx.app).post("/register-cnpj").set("X-B2B-Admin-Secret", ctx.config.adminSecret).send(defaultPayload())).status, 200);
  assert.equal(mutationCalls, 1);
});

test("structured logs contain no PII, query strings, secret or metafield values", async () => {
  const ctx = makeTestContext();
  const pii = "private-person@example.invalid";
  const secret = ctx.config.adminSecret;
  await request(ctx.app).post(`/admin/approve?secret=${encodeURIComponent(secret)}&email=${encodeURIComponent(pii)}`).send({ registration_id: newKey(), metafield_value: "sensitive-value" });
  const output = ctx.lines.join("\n");
  assert.equal(output.includes(pii), false);
  assert.equal(output.includes(secret), false);
  assert.equal(output.includes("sensitive-value"), false);
  assert.equal(output.includes("?secret="), false);
});

test("invalid webhook HMAC is rejected", async () => {
  const ctx = makeTestContext();
  const response = await request(ctx.app).post("/webhooks/shopify/customers-create")
    .set("Content-Type", "application/json").set("X-Shopify-Hmac-Sha256", "invalid")
    .send(JSON.stringify({ id: "123", email: "empresa@example.invalid" }));
  assert.equal(response.status, 401);
});

test("webhook is idempotent, handles no reservation, and binds exact customer id", async () => {
  const ctx = makeTestContext();
  const payload = Buffer.from(JSON.stringify({ id: "123456", email: "empresa@example.invalid" }));
  const hmac = crypto.createHmac("sha256", ctx.config.shopifyWebhookSecret).update(payload).digest("base64");
  const send = () => request(ctx.app).post("/webhooks/shopify/customers-create")
    .set("Content-Type", "application/json").set("X-Shopify-Hmac-Sha256", hmac)
    .set("X-Shopify-Webhook-Id", "synthetic-delivery-1").set("X-Shopify-Event-Id", "synthetic-event-1").send(payload.toString("utf8"));
  const noReservation = await send();
  assert.equal(noReservation.status, 202);
  assert.equal(noReservation.body.matched, false);
  const duplicate = await send();
  assert.equal(duplicate.body.duplicate, true);
  assert.equal(ctx.store.webhooks.has("synthetic-delivery-1"), true);
  assert.equal(ctx.store.webhooks.has("synthetic-event-1"), false);
  const storedWebhook = ctx.store.webhooks.get("synthetic-delivery-1");
  assert.equal(storedWebhook.payload_digest_version, DATA_DIGEST_VERSION);
  assert.equal(storedWebhook.payload_digest, webhookPayloadDigest(payload, ctx.config.dataDigestSecret));

  const registration = await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey()).send(defaultPayload({ email: "second@example.invalid" }));
  const secondPayload = Buffer.from(JSON.stringify({ id: "customer-opaque-2", email: "SECOND@example.invalid" }));
  const secondHmac = crypto.createHmac("sha256", ctx.config.shopifyWebhookSecret).update(secondPayload).digest("base64");
  const matched = await request(ctx.app).post("/webhooks/shopify/customers-create")
    .set("Content-Type", "application/json").set("X-Shopify-Hmac-Sha256", secondHmac)
    .set("X-Shopify-Event-Id", "synthetic-event-2").send(secondPayload.toString("utf8"));
  assert.equal(matched.status, 202);
  assert.equal(matched.body.matched, true);
  const stored = await ctx.store.getRegistration(registration.body.registration_id);
  assert.equal(stored.shopify_customer_id, "customer-opaque-2");
  assert.equal(stored.status, "pending_validation");
  assert.equal(ctx.store.outbox.size, 1);
});

test("public endpoints cannot mutate an existing customer", async () => {
  let legacyCalls = 0;
  const ctx = makeTestContext({ legacyMutationHandler: { async register() { legacyCalls += 1; } } });
  await request(ctx.app).post("/register-cnpj").send(defaultPayload({ email: "existing@example.invalid" }));
  await request(ctx.app).post("/validate-cnpj").send({ email: "existing@example.invalid", cnpj: defaultPayload().cnpj });
  await request(ctx.app).get("/validate-login?email=existing@example.invalid&cnpj=00000000000000");
  assert.equal(legacyCalls, 0);
  assert.equal(ctx.store.registrations.size, 0);
});
