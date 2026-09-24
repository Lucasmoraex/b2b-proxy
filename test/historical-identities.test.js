import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import request from "supertest";
import { DATA_DIGEST_VERSION } from "../src/data-digests.js";
import {
  assertReadOnlyGraphql,
  CUSTOMER_AUDIT_QUERY,
} from "../src/audit/shopify-customer-client.js";
import {
  buildHistoricalCustomerIdentityRecord,
  hashHistoricalIdentity,
  identityIndexSecretFingerprint,
  isHistoricalIdentityShopDomain,
  registrationIdentityClaims,
} from "../src/identity/historical-identities.js";
import { loadHistoricalIdentityImportConfig } from "../src/identity/import-config.js";
import { runHistoricalIdentityImportCommand } from "../src/identity/import-command.js";
import { HistoricalIdentityImporter } from "../src/services/historical-identity-importer.js";
import {
  acquireHistoricalAdvisoryLocks,
  acquireHistoricalPromotionExclusiveLock,
  acquireHistoricalPromotionSharedLock,
  historicalAdvisoryLockKeys,
  historicalPromotionLockKey,
} from "../src/storage/historical-locks.js";
import { MemoryRegistrationStore } from "../src/storage/memory-store.js";
import { persistedErrorRecord } from "../src/security.js";
import { defaultPayload, makeCnpj, makeTestContext, maskCnpj, newKey } from "./helpers.js";

const SHOP = "synthetic-history.myshopify.com";
const SECRET = "synthetic-identity-index-secret-32-characters-minimum";
const REGISTRATION_DATA_SECRET = "test-data-digest-secret-not-production-minimum-32";

const pages = async function* (...values) {
  for (const value of values) yield value;
};

const customer = (id, overrides = {}) => ({
  id: `gid://shopify/Customer/${id}`,
  email: `${id}@example.invalid`,
  phone: "+5511999990001",
  note: null,
  cnpj: { value: makeCnpj("123456789012") },
  cjnpj: null,
  cnpjStatus: { value: "approved" },
  tags: ["b2b-approved"],
  ...overrides,
});

const importerFor = (store, options = {}) => new HistoricalIdentityImporter({
  store,
  shopDomain: SHOP,
  identityIndexSecret: options.secret || SECRET,
  registrationIdentitySecret: options.registrationIdentitySecret || REGISTRATION_DATA_SECRET,
  clock: options.clock || (() => new Date("2030-01-01T00:00:00.000Z")),
  logger: options.logger,
});

const importCustomers = async (store, customers, options = {}) => importerFor(store, options).run({
  pages: pages(customers),
  dryRun: false,
  confirmation: "IMPORT_HISTORICAL_IDENTITIES",
});

const historyContext = (store, options = {}) => makeTestContext({
  store,
  registryClient: options.registryClient,
  config: {
    enableHistoricalIdentityLookup: true,
    identityIndexSecret: options.secret || SECRET,
    shop: SHOP,
  },
});

const register = (ctx, payload) => request(ctx.app)
  .post("/v1/registrations")
  .set("Idempotency-Key", newKey())
  .send(payload);

test("synthetic .invalid shop domains are accepted only when explicitly allowed", () => {
  assert.equal(isHistoricalIdentityShopDomain("synthetic-ui.example.invalid"), false);
  assert.equal(isHistoricalIdentityShopDomain("synthetic-ui.example.invalid", { allowSynthetic: true }), true);
  assert.equal(isHistoricalIdentityShopDomain("synthetic-ui.myshopify.com"), true);
  assert.equal(isHistoricalIdentityShopDomain("synthetic-ui.example.com", { allowSynthetic: true }), false);
});

test("unique historical email, CNPJ and phone claims block with public conflict codes before registry", async () => {
  const store = new MemoryRegistrationStore();
  const existing = customer("historical-unique");
  await importCustomers(store, [existing]);
  const ctx = historyContext(store);
  const cases = [
    [defaultPayload({ email: `  ${existing.email.toUpperCase()}  `, cnpj: makeCnpj("223456789012"), phone: "+5511999990002" }), "email_in_use"],
    [defaultPayload({ email: "new-cnpj@example.invalid", cnpj: maskCnpj(existing.cnpj.value), phone: "+5511999990003" }), "cnpj_in_use"],
    [defaultPayload({ email: "new-phone@example.invalid", cnpj: makeCnpj("323456789012"), phone: "(11) 99999-0001" }), "phone_in_use"],
  ];
  for (const [payload, code] of cases) {
    const response = await register(ctx, payload);
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, code);
  }
  assert.equal(ctx.registryCalls, 0);
});

test("conflicted historical claim remains representable and blocks without revealing multiplicity", async () => {
  const store = new MemoryRegistrationStore();
  const sharedCnpj = makeCnpj("423456789012");
  await importCustomers(store, [
    customer("duplicate-a", { email: "duplicate-a@example.invalid", phone: "+5511999990011", cnpj: { value: sharedCnpj } }),
    customer("duplicate-b", { email: "duplicate-b@example.invalid", phone: "+5511999990012", cnpj: { value: sharedCnpj } }),
  ]);
  const valueHash = hashHistoricalIdentity({ type: "cnpj", normalized: sharedCnpj, secret: SECRET });
  assert.equal(store.getHistoricalClaimState({ shopDomain: SHOP, type: "cnpj", valueHash }), "conflicted");

  const ctx = historyContext(store);
  const response = await register(ctx, defaultPayload({
    email: "new@example.invalid", cnpj: sharedCnpj, phone: "+5511999990013",
  }));
  assert.equal(response.status, 409);
  assert.equal(response.body.error.code, "cnpj_in_use");
  assert.equal(ctx.registryCalls, 0);
  assert.equal(JSON.stringify(response.body).includes("conflicted"), false);
});

test("invalid and incomplete historical values create state indicators but no usable claims", async () => {
  const store = new MemoryRegistrationStore();
  await importCustomers(store, [
    customer("invalid", { email: "invalid", phone: "+55000", cnpj: { value: "00000000000000" } }),
    customer("incomplete", { email: null, phone: null, cnpj: null }),
  ]);
  assert.equal(store.historicalIdentityMembers.size, 0);
  assert.equal(store.historicalIdentityStates.size, 6);
  const validities = [...store.historicalIdentityStates.values()].map((state) => state.validity);
  assert.equal(validities.filter((value) => value === "invalid").length, 3);
  assert.equal(validities.filter((value) => value === "incomplete").length, 3);
  assert.equal(JSON.stringify([...store.historicalIdentityStates.values()]).includes("00000000000000"), false);
});

test("repeated import is idempotent and exact Customer/type/hash membership is not duplicated", async () => {
  const store = new MemoryRegistrationStore();
  const fixture = customer("repeat");
  await importCustomers(store, [fixture]);
  await importCustomers(store, [fixture]);
  assert.equal(store.historicalIdentityMembers.size, 6);
  assert.equal(store.historicalIdentityStates.size, 6);
  assert.equal(store.historicalIdentityRuns.size, 2);
  const activeRunId = store.historicalIdentityMetadata.get(SHOP).active_import_run_id;
  assert.equal([...store.historicalIdentityMembers.values()]
    .filter((member) => member.import_run_id === activeRunId).length, 3);
});

test("two Customers may share one hash and derive active versus conflicted state", async () => {
  const store = new MemoryRegistrationStore();
  const sharedPhone = "+5511999990021";
  const first = customer("shared-a", { phone: sharedPhone, email: "shared-a@example.invalid" });
  await importCustomers(store, [first]);
  const valueHash = hashHistoricalIdentity({ type: "phone", normalized: sharedPhone, secret: SECRET });
  assert.equal(store.getHistoricalClaimState({ shopDomain: SHOP, type: "phone", valueHash }), "active");
  await importCustomers(store, [customer("shared-b", { phone: sharedPhone, email: "shared-b@example.invalid" })]);
  assert.equal(store.getHistoricalClaimState({ shopDomain: SHOP, type: "phone", valueHash }), "conflicted");
  const activeRunId = store.historicalIdentityMetadata.get(SHOP).active_import_run_id;
  const matching = [...store.historicalIdentityMembers.values()].filter((member) => (
    member.import_run_id === activeRunId && member.value_hash === valueHash
  ));
  assert.equal(matching.length, 2);
});

test("dry-run computes aggregate totals without calling any storage write", async () => {
  const store = new Proxy({}, {
    get() { throw new Error("dry_run_must_not_access_store"); },
  });
  const summary = await importerFor(store).run({
    pages: pages([customer("dry-run")]),
    dryRun: true,
  });
  assert.equal(summary.dry_run, true);
  assert.equal(summary.customers_scanned, 1);
  assert.equal(summary.claims_processed, 3);
  assert.deepEqual(summary.identity_states, {
    email: { valid: 1, invalid: 0, incomplete: 0 },
    cnpj: { valid: 1, invalid: 0, incomplete: 0 },
    phone: { valid: 1, invalid: 0, incomplete: 0 },
  });
  assert.deepEqual(summary.claims, {
    email: { active: 1, conflicted: 0, duplicate_groups: 0, members: 1 },
    cnpj: { active: 1, conflicted: 0, duplicate_groups: 0, members: 1 },
    phone: { active: 1, conflicted: 0, duplicate_groups: 0, members: 1 },
  });
});

test("dry-run aggregates distinct Customers deterministically without exposing identifiers or hashes", async () => {
  const sharedCnpj = makeCnpj("823456789012");
  const uniqueCnpj = makeCnpj("923456789012");
  const fixtures = [
    customer("aggregate-a", { email: "shared@example.invalid", phone: "+5511999990061", cnpj: { value: sharedCnpj } }),
    customer("aggregate-b", { email: "shared@example.invalid", phone: "+5511999990061", cnpj: { value: sharedCnpj } }),
    customer("aggregate-invalid", { email: "invalid", phone: "+55000", cnpj: { value: "00000000000000" } }),
    customer("aggregate-incomplete", { email: null, phone: null, cnpj: null }),
    customer("aggregate-unique", { email: "unique@example.invalid", phone: "+5511999990062", cnpj: { value: uniqueCnpj } }),
  ];
  const runOnce = () => importerFor(new Proxy({}, {
    get() { throw new Error("dry_run_must_not_access_store"); },
  }), { clock: () => new Date("2030-01-01T00:00:00.000Z") }).run({
    pages: pages(fixtures),
    dryRun: true,
  });
  const first = await runOnce();
  const second = await runOnce();
  assert.deepEqual(first.identity_states, second.identity_states);
  assert.deepEqual(first.claims, second.claims);
  for (const type of ["email", "cnpj", "phone"]) {
    assert.deepEqual(first.identity_states[type], { valid: 3, invalid: 1, incomplete: 1 });
    assert.deepEqual(first.claims[type], { active: 1, conflicted: 1, duplicate_groups: 1, members: 3 });
  }
  const output = JSON.stringify(first);
  for (const forbidden of [
    "shared@example.invalid", "+5511999990061", sharedCnpj,
    "gid://shopify/Customer/aggregate-a", "CNPJ:", "CEL:",
  ]) assert.equal(output.includes(forbidden), false);
  assert.doesNotMatch(output, /\b[0-9a-f]{64}\b/i);
});

test("dry-run command never reads DATABASE_URL, constructs pg.Pool or creates a report", async (t) => {
  const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "b2b-identity-dry-run-"));
  t.after(() => fs.rm(temporaryRoot, { recursive: true, force: true }));
  const previousCwd = process.cwd();
  const values = {
    B2B_ENVIRONMENT: "production",
    B2B_IDENTITY_IMPORT_MODE: "dry-run",
    B2B_ENABLE_HISTORICAL_IDENTITY_IMPORT: "false",
    B2B_ALLOW_PRODUCTION_IDENTITY_IMPORT: "false",
    B2B_IDENTITY_IMPORT_CONFIRMED_SHOP_DOMAIN: SHOP,
    B2B_IDENTITY_INDEX_SECRET: SECRET,
    B2B_DATA_DIGEST_SECRET: "synthetic-historical-import-data-digest-secret-32",
    SHOPIFY_SHOP: SHOP,
    SHOPIFY_ADMIN_TOKEN: "synthetic-read-only-token",
    SHOPIFY_API_VERSION: "2026-07",
  };
  const env = new Proxy(values, {
    get(target, property) {
      if (property === "DATABASE_URL") throw new Error("dry_run_must_not_read_database_url");
      return target[property];
    },
  });
  class ExplodingPool {
    constructor() { throw new Error("dry_run_must_not_construct_pool"); }
  }
  let stdout = "";
  const fetchImpl = async (_url, options) => {
    const requestBody = JSON.parse(options.body);
    assert.equal(assertReadOnlyGraphql(requestBody.query), CUSTOMER_AUDIT_QUERY);
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      async json() {
        return { data: { customers: { nodes: [customer("command-dry-run")], pageInfo: { hasNextPage: false, endCursor: null } } } };
      },
    };
  };
  try {
    process.chdir(temporaryRoot);
    const summary = await runHistoricalIdentityImportCommand({
      env,
      fetchImpl,
      PoolClass: ExplodingPool,
      logger: { info() {}, warn() {}, error() {} },
      stdout: { write: (chunk) => { stdout += chunk; } },
      durationClock: (() => { const values = [100, 125]; return () => values.shift(); })(),
    });
    assert.equal(summary.duration_ms, 25);
    assert.deepEqual(await fs.readdir(temporaryRoot), []);
  } finally {
    process.chdir(previousCwd);
  }
  for (const forbidden of [
    "command-dry-run@example.invalid", "+5511999990001",
    "gid://shopify/Customer/command-dry-run", SECRET, "synthetic-read-only-token",
  ]) assert.equal(stdout.includes(forbidden), false);
  assert.doesNotMatch(stdout, /\b[0-9a-f]{64}\b/i);
});

test("historical advisory locks use one deterministic lexical transaction-level helper", async () => {
  const claims = [
    { type: "phone", valueHash: "f".repeat(64) },
    { type: "email", valueHash: "e".repeat(64) },
    { type: "cnpj", valueHash: "c".repeat(64) },
    { type: "email", valueHash: "e".repeat(64) },
  ];
  const keys = historicalAdvisoryLockKeys(SHOP, claims);
  assert.deepEqual(keys.map((key) => key.split(":")[1]), ["cnpj", "email", "phone"]);
  const calls = [];
  const client = { async query(sql, params) { calls.push({ sql, params }); } };
  assert.deepEqual(await acquireHistoricalAdvisoryLocks(client, SHOP, [...claims].reverse()), keys);
  assert.deepEqual(calls.map((call) => call.params[0]), keys);
  assert.ok(calls.every((call) => call.sql === "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"));

  calls.length = 0;
  const promotionKey = historicalPromotionLockKey(SHOP);
  assert.equal(await acquireHistoricalPromotionSharedLock(client, SHOP), promotionKey);
  assert.equal(await acquireHistoricalPromotionExclusiveLock(client, SHOP), promotionKey);
  assert.deepEqual(calls, [
    { sql: "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))", params: [promotionKey] },
    { sql: "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", params: [promotionKey] },
  ]);
});

test("import query is the fixed read-only allowlist and mutations or subscriptions are impossible", () => {
  assert.equal(assertReadOnlyGraphql(CUSTOMER_AUDIT_QUERY), CUSTOMER_AUDIT_QUERY);
  assert.throws(() => assertReadOnlyGraphql("mutation Unsafe { customerDelete(input: {}) { deletedCustomerId } }"), /audit_query_only/);
  assert.throws(() => assertReadOnlyGraphql("subscription Unsafe { event { id } }"), /audit_query_only/);
  assert.throws(() => assertReadOnlyGraphql("query Different { shop { id } }"), /audit_query_not_allowlisted/);
});

test("historical lookup is registration-only and never participates in legacy login", async () => {
  const store = new MemoryRegistrationStore();
  let historicalLookups = 0;
  store.findHistoricalConflict = async () => {
    historicalLookups += 1;
    return null;
  };
  const ctx = historyContext(store);
  const response = await request(ctx.app).get("/validate-login?email=synthetic%40example.invalid&cnpj=00000000000000");
  assert.equal(response.status, 410);
  assert.equal(response.body.error.code, "legacy_login_removed");
  assert.equal(historicalLookups, 0);
  assert.equal(ctx.registryCalls, 0);
});

test("historical import derives an index without mutating the source Customer", async () => {
  const store = new MemoryRegistrationStore();
  const fixture = customer("immutable-source", {
    email: "immutable-source@example.invalid",
    phone: "+5511999990088",
    cnpj: { value: makeCnpj("633456789012") },
    note: "CNPJ: 63345678901200 | CEL: 11999990088",
  });
  const original = structuredClone(fixture);
  await importCustomers(store, [fixture]);
  assert.deepEqual(fixture, original);
  assert.equal(store.registrations.size, 0);
  assert.equal(store.historicalIdentityMetadata.get(SHOP).active_import_run_id !== null, true);
});

test("write import requires all operational locks and production is refused by default", () => {
  const base = {
    B2B_ENVIRONMENT: "staging",
    B2B_IDENTITY_IMPORT_MODE: "write",
    B2B_ENABLE_HISTORICAL_IDENTITY_IMPORT: "true",
    B2B_IDENTITY_IMPORT_CONFIRMATION: "IMPORT_HISTORICAL_IDENTITIES",
    B2B_IDENTITY_IMPORT_CONFIRMED_SHOP_DOMAIN: SHOP,
    B2B_IDENTITY_INDEX_SECRET: SECRET,
    B2B_DATA_DIGEST_SECRET: "synthetic-historical-write-data-digest-secret-32",
    SHOPIFY_SHOP: SHOP,
    SHOPIFY_ADMIN_TOKEN: "synthetic-read-token",
    SHOPIFY_API_VERSION: "2026-07",
    DATABASE_URL: "postgres://synthetic.invalid/never-used",
  };
  assert.equal(loadHistoricalIdentityImportConfig(base).dryRun, false);
  assert.equal(loadHistoricalIdentityImportConfig({ ...base, B2B_IDENTITY_IMPORT_MAX_RETRIES: "0" }).maxRetries, 0);
  assert.throws(() => loadHistoricalIdentityImportConfig({ ...base, B2B_ENABLE_HISTORICAL_IDENTITY_IMPORT: "false" }), /identity_import_disabled/);
  assert.throws(() => loadHistoricalIdentityImportConfig({ ...base, B2B_IDENTITY_IMPORT_CONFIRMATION: "wrong" }), /identity_import_confirmation_required/);
  assert.throws(() => loadHistoricalIdentityImportConfig({ ...base, B2B_ENVIRONMENT: "production" }), /identity_import_production_refused/);
  assert.throws(() => loadHistoricalIdentityImportConfig({ ...base, B2B_IDENTITY_INDEX_SECRET: "too-short" }), /identity_index_secret_invalid/);
  assert.throws(() => loadHistoricalIdentityImportConfig({ ...base, B2B_ADMIN_SECRET: SECRET }), /identity_index_secret_reuse_forbidden/);
});

test("secret absence or rotation fails closed before registry lookup", async () => {
  const store = new MemoryRegistrationStore();
  await importCustomers(store, [customer("secret-a")]);
  const ctx = historyContext(store, { secret: "different-synthetic-identity-secret-at-least-32-chars" });
  const response = await register(ctx, defaultPayload({
    email: "unrelated@example.invalid", cnpj: makeCnpj("523456789012"), phone: "+5511999990031",
  }));
  assert.equal(response.status, 503);
  assert.equal(response.body.error.code, "identity_index_unavailable");
  assert.equal(ctx.registryCalls, 0);
});

test("logs, stored claims and errors contain no raw PII or identity secret", async () => {
  const store = new MemoryRegistrationStore();
  const lines = [];
  const logger = {
    info: (event, context) => lines.push(JSON.stringify({ event, context })),
    warn: (event, context) => lines.push(JSON.stringify({ event, context })),
    error: (event, context) => lines.push(JSON.stringify({ event, context: context ? Object.keys(context) : [] })),
  };
  const fixture = customer("privacy", {
    email: "private-person@example.invalid",
    phone: "+5511999990041",
    cnpj: { value: makeCnpj("623456789012") },
  });
  await importCustomers(store, [fixture], { logger });
  const serialized = JSON.stringify([...store.historicalIdentityMembers.values()]);
  const output = lines.join("\n");
  for (const forbidden of [fixture.email, fixture.phone, fixture.cnpj.value, SECRET]) {
    assert.equal(serialized.includes(forbidden), false);
    assert.equal(output.includes(forbidden), false);
  }
});

test("import winning the registration race is rechecked atomically and registration fails safely", async () => {
  const store = new MemoryRegistrationStore();
  await importerFor(store).run({ pages: pages([]), dryRun: false, confirmation: "IMPORT_HISTORICAL_IDENTITIES" });
  let releaseRegistry;
  let registryStarted;
  const started = new Promise((resolve) => { registryStarted = resolve; });
  const registryClient = {
    async checkCnpj() {
      registryStarted();
      await new Promise((resolve) => { releaseRegistry = resolve; });
      return { found: true, active: true, status: "ATIVA" };
    },
  };
  const ctx = historyContext(store, { registryClient });
  const payload = defaultPayload({
    email: "race@example.invalid", cnpj: makeCnpj("723456789012"), phone: "+5511999990051",
  });
  const pendingRegistration = Promise.resolve(register(ctx, payload));
  await started;
  await importCustomers(store, [customer("race", {
    email: payload.email, cnpj: { value: payload.cnpj }, phone: payload.phone,
  })]);
  releaseRegistry();
  const response = await pendingRegistration;
  assert.equal(response.status, 409);
  assert.equal(response.body.error.code, "email_in_use");
  assert.equal(store.registrations.size, 0);
});

test("metadata fingerprint is stable but a replacement secret cannot initialize the same shop", async () => {
  const store = new MemoryRegistrationStore();
  await importCustomers(store, [customer("metadata")]);
  assert.equal(
    store.historicalIdentityMetadata.get(SHOP).secret_fingerprint,
    identityIndexSecretFingerprint(SECRET),
  );
  await assert.rejects(
    importCustomers(store, [customer("metadata-2")], { secret: "replacement-synthetic-identity-index-secret-32-chars" }),
    /identity_index_unavailable/,
  );
});

const stageCustomers = async (store, customers, runId = newKey(), now = new Date("2030-01-01T00:00:00.000Z")) => {
  const secretFingerprint = identityIndexSecretFingerprint(SECRET);
  await store.beginHistoricalIdentityImport({ runId, shopDomain: SHOP, secretFingerprint, now });
  await store.importHistoricalIdentityPage({
    runId,
    shopDomain: SHOP,
    secretFingerprint,
    customers: customers.map((fixture) => buildHistoricalCustomerIdentityRecord(
      fixture,
      SECRET,
      REGISTRATION_DATA_SECRET,
    )),
    now,
  });
  return { runId, secretFingerprint, now };
};

const promoteRun = (store, staged) => store.completeHistoricalIdentityImport({
  ...staged,
  shopDomain: SHOP,
  identityIndexSecret: SECRET,
  summary: { pages_scanned: 1, customers_scanned: 1, claims_processed: 3, states_processed: 3 },
});

const claimsFor = (fixture) => registrationIdentityClaims({
  email: fixture.email,
  cnpj: fixture.cnpj.value,
  phone: fixture.phone,
  secret: SECRET,
});

test("failure after multiple pages preserves staged diagnostics but exposes zero active claims", async () => {
  class FailSecondPageStore extends MemoryRegistrationStore {
    page = 0;

    async importHistoricalIdentityPage(input) {
      this.page += 1;
      if (this.page === 2) throw new Error("synthetic_page_failure");
      return super.importHistoricalIdentityPage(input);
    }
  }
  const store = new FailSecondPageStore();
  const first = customer("failed-page-one");
  await assert.rejects(importerFor(store).run({
    pages: pages([first], [customer("failed-page-two", {
      email: "second-page@example.invalid",
      phone: "+5511999990072",
      cnpj: { value: makeCnpj("133456789012") },
    })]),
    dryRun: false,
    confirmation: "IMPORT_HISTORICAL_IDENTITIES",
  }), /synthetic_page_failure/);

  assert.ok(store.historicalIdentityMembers.size > 0);
  assert.equal([...store.historicalIdentityRuns.values()][0].status, "failed");
  assert.equal(store.historicalIdentityMetadata.get(SHOP).active_import_run_id, null);
  await assert.rejects(store.findHistoricalConflict({
    shopDomain: SHOP,
    secretFingerprint: identityIndexSecretFingerprint(SECRET),
    claims: claimsFor(first),
  }), (error) => error.code === "identity_index_unavailable" && error.status === 503);
});

test("staged snapshot is invisible until atomic promotion", async () => {
  const store = new MemoryRegistrationStore();
  const fixture = customer("staged-invisible");
  const staged = await stageCustomers(store, [fixture]);
  await assert.rejects(store.findHistoricalConflict({
    shopDomain: SHOP,
    secretFingerprint: staged.secretFingerprint,
    claims: claimsFor(fixture),
  }), (error) => error.code === "identity_index_unavailable");

  await promoteRun(store, staged);
  assert.equal(await store.findHistoricalConflict({
    shopDomain: SHOP,
    secretFingerprint: staged.secretFingerprint,
    claims: claimsFor(fixture),
  }), "email_in_use");
  assert.equal(store.historicalIdentityMetadata.get(SHOP).active_import_run_id, staged.runId);
});

test("failed refresh neither replaces nor supplements the prior active snapshot", async () => {
  const store = new MemoryRegistrationStore();
  const active = customer("active-snapshot");
  await importCustomers(store, [active]);
  const activeRunId = store.historicalIdentityMetadata.get(SHOP).active_import_run_id;

  const failed = customer("failed-refresh", {
    email: "failed-refresh@example.invalid",
    phone: "+5511999990073",
    cnpj: { value: makeCnpj("233456789012") },
  });
  const staged = await stageCustomers(store, [failed]);
  await store.failHistoricalIdentityImport({
    runId: staged.runId,
    error: persistedErrorRecord(Object.assign(new Error("synthetic_failure"), { code: "historical_identity_import_failed" }), { defaultCategory: "historical_identity" }),
    now: staged.now,
  });

  assert.equal(store.historicalIdentityMetadata.get(SHOP).active_import_run_id, activeRunId);
  assert.equal(await store.findHistoricalConflict({
    shopDomain: SHOP, secretFingerprint: staged.secretFingerprint, claims: claimsFor(active),
  }), "email_in_use");
  assert.equal(await store.findHistoricalConflict({
    shopDomain: SHOP, secretFingerprint: staged.secretFingerprint, claims: claimsFor(failed),
  }), null);
  const activeMembers = [...store.historicalIdentityMembers.values()]
    .filter((member) => member.import_run_id === activeRunId);
  assert.equal(activeMembers.length, 3);
});

test("global promotion revalidation detects a registration created after page processing", async () => {
  const store = new MemoryRegistrationStore();
  const fixture = customer("late-registration", {
    email: "late-registration@example.invalid",
    phone: "+5511999990074",
    cnpj: { value: makeCnpj("333456789012") },
  });
  const staged = await stageCustomers(store, [fixture]);
  await store.reserve({
    email: fixture.email,
    cnpj: fixture.cnpj.value,
    phone: fixture.phone,
    idempotencyKey: newKey(),
    requestDigest: "a".repeat(64),
    requestDigestVersion: DATA_DIGEST_VERSION,
    fiscalStatus: "ATIVA",
    now: staged.now,
    expiresAt: new Date(staged.now.getTime() + 60_000),
  });

  await assert.rejects(promoteRun(store, staged), /historical_identity_registration_conflict/);
  assert.equal(store.historicalIdentityRuns.get(staged.runId).status, "staging");
  assert.equal(store.historicalIdentityMetadata.get(SHOP).active_import_run_id, null);
  await store.failHistoricalIdentityImport({
    runId: staged.runId,
    error: persistedErrorRecord(Object.assign(new Error("synthetic"), { code: "historical_identity_registration_conflict" }), { defaultCategory: "historical_identity" }),
    now: staged.now,
  });
  assert.equal(store.historicalIdentityRuns.get(staged.runId).status, "failed");
});

test("historical promotion revalidates minimized registration claims without plaintext", async () => {
  const store = new MemoryRegistrationStore();
  const fixture = customer("minimized-late-registration", {
    email: "minimized-late@example.invalid",
    phone: "+5511999990174",
    cnpj: { value: makeCnpj("343456789012") },
  });
  const staged = await stageCustomers(store, [fixture]);
  const ctx = makeTestContext({ store });
  const response = await request(ctx.app).post("/v1/registrations")
    .set("Idempotency-Key", newKey())
    .send({ email: fixture.email, cnpj: fixture.cnpj.value, phone: fixture.phone });
  assert.equal(response.status, 201);
  assert.equal(store.registrations.get(response.body.registration_id).email_normalized, null);
  await assert.rejects(promoteRun(store, staged), /historical_identity_registration_conflict/);
});

test("lookup enabled without a completed active snapshot fails closed before registry", async () => {
  const store = new MemoryRegistrationStore();
  const staged = await stageCustomers(store, [customer("no-active-snapshot")]);
  const ctx = historyContext(store);
  const response = await register(ctx, defaultPayload({
    email: "new-no-active@example.invalid",
    cnpj: makeCnpj("433456789012"),
    phone: "+5511999990075",
  }));
  assert.equal(response.status, 503);
  assert.equal(response.body.error.code, "identity_index_unavailable");
  assert.equal(ctx.registryCalls, 0);
  assert.equal(store.historicalIdentityRuns.get(staged.runId).status, "staging");
});

test("only the promoted completed snapshot contributes claims after successive runs", async () => {
  const store = new MemoryRegistrationStore();
  const original = customer("original-active");
  await importCustomers(store, [original]);
  const previousRunId = store.historicalIdentityMetadata.get(SHOP).active_import_run_id;
  const refreshed = customer("refreshed-active", {
    email: "refreshed@example.invalid",
    phone: "+5511999990076",
    cnpj: { value: makeCnpj("533456789012") },
  });
  await importCustomers(store, [refreshed]);
  const currentRunId = store.historicalIdentityMetadata.get(SHOP).active_import_run_id;

  assert.notEqual(currentRunId, previousRunId);
  assert.equal([...store.historicalIdentityRuns.values()]
    .filter((run) => run.id === currentRunId && run.status === "completed").length, 1);
  assert.equal([...store.historicalIdentityMembers.values()]
    .filter((member) => member.import_run_id === currentRunId).length, 6);
  assert.equal(await store.findHistoricalConflict({
    shopDomain: SHOP,
    secretFingerprint: identityIndexSecretFingerprint(SECRET),
    claims: claimsFor(original),
  }), "email_in_use");
  assert.equal(await store.findHistoricalConflict({
    shopDomain: SHOP,
    secretFingerprint: identityIndexSecretFingerprint(SECRET),
    claims: claimsFor(refreshed),
  }), "email_in_use");
});
