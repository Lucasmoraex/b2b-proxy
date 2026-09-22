import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import request from "supertest";
import { assertSimulationSafety, SimulatedRegistryClient, SimulatedShopifyClient, SIMULATION_CONFIRMATION } from "../src/simulation.js";
import { OutboxWorker } from "../src/worker.js";
import { defaultPayload, makeCnpj, makeTestContext, newKey } from "./helpers.js";

const simulationConfig = {
  environment: "staging", nodeEnv: "development", simulationMode: true,
  simulationConfirmation: SIMULATION_CONFIRMATION, shop: "simulation.example.invalid",
  shopifyToken: "", shopifyClientId: "", shopifyClientSecret: "", registryToken: "",
  shopifyWebhookSecret: "sim_test-webhook-secret", autoApprove: false,
  enableLegacyMutations: false, isRender: true, renderServiceName: "b2b-v2-staging",
};

test("simulation safety fails closed in production and with external credentials", () => {
  assert.throws(() => assertSimulationSafety({ ...simulationConfig, nodeEnv: "production" }), /forbidden/);
  assert.throws(() => assertSimulationSafety({ ...simulationConfig, shopifyToken: "not-allowed" }), /refuses/);
  assert.throws(() => assertSimulationSafety({ ...simulationConfig, renderServiceName: "b2b-production" }), /staging/);
  assert.doesNotThrow(() => assertSimulationSafety(simulationConfig));
});

test("simulation mode covers registry, webhook, worker and approval without external calls", async () => {
  const registryClient = new SimulatedRegistryClient({ scenario: "active" });
  const controller = {
    getRegistryScenario: () => registryClient.getScenario(),
    setRegistryScenario: (scenario) => registryClient.setScenario(scenario),
  };
  const ctx = makeTestContext({
    registryClient, simulationController: controller,
    config: { ...simulationConfig, registrationTokenSecret: "synthetic-registration-secret" },
  });
  const admin = { "X-B2B-Admin-Secret": ctx.config.adminSecret };

  const accepted = await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey()).send(defaultPayload());
  assert.equal(accepted.status, 201);

  const duplicateCases = [
    ["email_in_use", { cnpj: makeCnpj("133456789012"), phone: "+5511999990011" }],
    ["cnpj_in_use", { email: "other-cnpj@example.invalid", phone: "+5511999990012" }],
    ["phone_in_use", { email: "other-phone@example.invalid", cnpj: makeCnpj("143456789012") }],
  ];
  for (const [code, overrides] of duplicateCases) {
    const duplicate = await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey())
      .send(defaultPayload(overrides));
    assert.equal(duplicate.status, 409);
    assert.equal(duplicate.body.error.code, code);
  }

  await request(ctx.app).post("/admin/simulation/registry").set(admin).send({ scenario: "inactive" }).expect(200);
  const inactive = await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey())
    .send(defaultPayload({ email: "inactive@example.invalid", cnpj: makeCnpj("223456789012"), phone: "+5511999990021" }));
  assert.equal(inactive.body.error.code, "inactive_cnpj");

  await request(ctx.app).post("/admin/simulation/registry").set(admin).send({ scenario: "unavailable" }).expect(200);
  const unavailable = await request(ctx.app).post("/v1/registrations").set("Idempotency-Key", newKey())
    .send(defaultPayload({ email: "unavailable@example.invalid", cnpj: makeCnpj("323456789012"), phone: "+5511999990022" }));
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.error.code, "registry_unavailable");
  await request(ctx.app).post("/admin/simulation/registry").set(admin).send({ scenario: "active" }).expect(200);

  const webhookBody = JSON.stringify({ id: "synthetic-customer-staging", email: defaultPayload().email });
  const hmac = crypto.createHmac("sha256", ctx.config.shopifyWebhookSecret).update(webhookBody).digest("base64");
  await request(ctx.app).post("/webhooks/shopify/customers-create")
    .set("Content-Type", "application/json").set("X-Shopify-Hmac-Sha256", hmac)
    .set("X-Shopify-Webhook-Id", "synthetic-simulation-delivery").send(webhookBody).expect(202);

  const shopifyClient = new SimulatedShopifyClient({ store: ctx.store });
  const worker = new OutboxWorker({ store: ctx.store, shopifyClient, clock: ctx.clock, logger: ctx.logger });
  await worker.runOnce();
  const pending = await ctx.store.getRegistration(accepted.body.registration_id);
  assert.equal(pending.status, "pending_review");

  const simulatedPending = await request(ctx.app).get("/admin/simulation/shopify/synthetic-customer-staging").set(admin);
  assert.ok(simulatedPending.body.customer.tags.includes("b2b-pending"));
  assert.equal(simulatedPending.body.customer.metafields.nodes.find((field) => field.key === "cnpj_status").value, "pending");

  await request(ctx.app).post("/admin/approve").set(admin).send({ registration_id: accepted.body.registration_id }).expect(202);
  await worker.runOnce();
  const approved = await ctx.store.getRegistration(accepted.body.registration_id);
  assert.equal(approved.status, "approved");
  const simulatedApproved = await ctx.store.getSimulationCustomer("synthetic-customer-staging");
  assert.ok(simulatedApproved.tags.includes("b2b-approved"));
  assert.equal(simulatedApproved.metafields.nodes.find((field) => field.key === "cnpj_status").value, "approved");
});
