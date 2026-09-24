import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  auditShopifyCustomers,
  auditSummary,
  extractLegacyNote,
} from "../src/audit/customer-audit.js";
import { loadCustomerAuditConfig } from "../src/audit/config.js";
import { writeCustomerAuditReport } from "../src/audit/report.js";
import {
  assertReadOnlyGraphql,
  CUSTOMER_AUDIT_QUERY,
  ReadOnlyShopifyCustomerClient,
} from "../src/audit/shopify-customer-client.js";
import { createReadOnlyTelemetry, readOnlyTelemetrySummary } from "../src/audit/read-only-telemetry.js";

const fixturePages = JSON.parse(await fs.readFile(
  new URL("./fixtures/shopify-customers-pages.json", import.meta.url),
  "utf8",
));

const response = (body, status = 200, headers = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: { get: (name) => headers[String(name).toLowerCase()] || null },
  async json() { return body; },
});

const makePagedClient = ({ calls = [] } = {}) => new ReadOnlyShopifyCustomerClient({
  fetchImpl: async (_url, options) => {
    const request = JSON.parse(options.body);
    calls.push(request);
    assert.equal(options.method, "POST");
    assertReadOnlyGraphql(request.query);
    const page = request.variables.after ? fixturePages[1] : fixturePages[0];
    return response({ data: page });
  },
  shopDomain: "synthetic-audit.myshopify.com",
  token: "synthetic-token-never-sent",
  apiVersion: "2026-07",
  sleep: async () => {},
});

test("paginates all customers and detects duplicates, invalid data and divergences", async () => {
  const calls = [];
  const report = await auditShopifyCustomers({
    client: makePagedClient({ calls }),
    shopDomain: "synthetic-audit.myshopify.com",
    apiVersion: "2026-07",
    clock: () => new Date("2030-01-01T00:00:00.000Z"),
    hashKey: Buffer.alloc(32, 7),
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].variables.after, null);
  assert.equal(calls[1].variables.after, "synthetic-cursor-1");
  assert.equal(report.totals.pages_scanned, 2);
  assert.equal(report.totals.customers_scanned, 5);
  assert.equal(report.categories.duplicate_emails, 1);
  assert.equal(report.categories.duplicate_cnpjs, 1);
  assert.equal(report.categories.duplicate_phones, 1);
  assert.equal(report.categories.invalid_emails, 1);
  assert.equal(report.categories.invalid_cnpjs, 1);
  assert.equal(report.categories.invalid_phones, 1);
  assert.equal(report.categories.missing_cnpj, 2);
  assert.equal(report.categories.missing_cnpj_status, 2);
  assert.equal(report.categories.approved_tag_without_valid_cnpj, 1);
  assert.equal(report.categories.approved_tag_without_approved_status, 2);
  assert.equal(report.categories.approved_status_without_approved_tag, 1);
  assert.equal(report.categories.pending_and_approved_tags, 1);
  assert.equal(report.categories.cnpj_source_divergence, 2);
  assert.equal(report.categories.official_phone_note_divergence, 2);
  assert.equal(report.customer_indicators.length, 5);
  const firstIndicator = report.customer_indicators.find((customer) => customer.customer_id.endsWith("synthetic-001"));
  assert.deepEqual(firstIndicator.email, { present: true, valid: true });
  assert.equal(firstIndicator.phone.state, "both");
  assert.equal(firstIndicator.cnpj_status, "approved");
  assert.equal(firstIndicator.has_b2b_approved, true);
  assert.equal(firstIndicator.cnpj_sources.filter((source) => source.state === "valid").length, 3);
});

test("retries a throttled GraphQL query without exposing protected data in logs", async () => {
  let calls = 0;
  const delays = [];
  const logs = [];
  const telemetry = createReadOnlyTelemetry();
  const client = new ReadOnlyShopifyCustomerClient({
    fetchImpl: async (_url, options) => {
      calls += 1;
      const request = JSON.parse(options.body);
      assertReadOnlyGraphql(request.query);
      if (calls === 1) {
        return response({
          errors: [{ message: "synthetic throttling", extensions: { code: "THROTTLED" } }],
          extensions: { cost: { requestedQueryCost: 50, throttleStatus: { currentlyAvailable: 0, restoreRate: 100 } } },
        });
      }
      return response({ data: { customers: { nodes: [], pageInfo: { hasNextPage: false, endCursor: null } } } });
    },
    shopDomain: "synthetic-audit.myshopify.com",
    token: "secret-token-must-not-appear",
    apiVersion: "2026-07",
    maxRetries: 2,
    sleep: async (delay) => delays.push(delay),
    logger: { warn: (event, context) => logs.push(JSON.stringify({ event, ...context })) },
    telemetry,
  });

  const pages = [];
  for await (const page of client.customerPages()) pages.push(page);
  assert.equal(calls, 2);
  assert.deepEqual(pages, [[]]);
  assert.deepEqual(delays, [500]);
  assert.deepEqual(readOnlyTelemetrySummary(telemetry), {
    retries_total: 1,
    errors_by_category: { throttled_graphql: 1 },
  });
  const logText = logs.join("\n");
  assert.doesNotMatch(logText, /secret-token|example\.invalid|CNPJ|CEL/i);
});

test("read-only client rejects mutation and subscription documents", () => {
  assert.equal(assertReadOnlyGraphql(CUSTOMER_AUDIT_QUERY), CUSTOMER_AUDIT_QUERY);
  assert.throws(() => assertReadOnlyGraphql("query OtherReadOnlyQuery { shop { id } }"), /audit_query_not_allowlisted/);
  assert.throws(() => assertReadOnlyGraphql("mutation Unsafe { customerDelete(input: {}) { deletedCustomerId } }"), /audit_query_only/);
  assert.throws(() => assertReadOnlyGraphql("subscription Unsafe { event { id } }"), /audit_query_only/);
  const client = makePagedClient();
  assert.equal(client.execute, undefined);
  assert.equal(client.mutate, undefined);
});

test("configuration requires read-only confirmation and never reads DATABASE_URL", () => {
  const values = {
    B2B_AUDIT_CONFIRMATION: "READ_ONLY_CUSTOMER_AUDIT",
    B2B_AUDIT_MODE: "read-only",
    SHOPIFY_SHOP: "synthetic-audit.myshopify.com",
    B2B_AUDIT_CONFIRMED_SHOP_DOMAIN: "synthetic-audit.myshopify.com",
    SHOPIFY_ADMIN_TOKEN: "synthetic-token",
    SHOPIFY_API_VERSION: "2026-07",
  };
  const env = new Proxy(values, {
    get(target, property) {
      if (property === "DATABASE_URL") throw new Error("DATABASE_URL must not be read");
      return target[property];
    },
  });
  const config = loadCustomerAuditConfig(env);
  assert.equal(config.shopDomain, values.SHOPIFY_SHOP);
  assert.throws(() => loadCustomerAuditConfig({ ...values, B2B_AUDIT_MODE: "write" }), /audit_read_only_mode_required/);
  assert.throws(() => loadCustomerAuditConfig({ ...values, B2B_AUDIT_CONFIRMED_SHOP_DOMAIN: "other.myshopify.com" }), /audit_shop_confirmation_mismatch/);
  assert.throws(() => loadCustomerAuditConfig({ ...values, B2B_AUDIT_CONFIRMATION: "wrong" }), /audit_confirmation_required/);
});

test("writes a mode-600 report without PII and keeps stdout summary aggregate-only", async (t) => {
  const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "b2b-audit-test-"));
  t.after(() => fs.rm(temporaryRoot, { recursive: true, force: true }));
  const report = await auditShopifyCustomers({
    client: makePagedClient(),
    shopDomain: "synthetic-audit.myshopify.com",
    apiVersion: "2026-07",
    clock: () => new Date("2030-01-01T00:00:00.000Z"),
    hashKey: Buffer.alloc(32, 9),
  });
  const reportPath = await writeCustomerAuditReport(report, { cwd: temporaryRoot });
  assert.equal(path.dirname(reportPath), path.join(temporaryRoot, ".shopify-audit-reports"));
  const stat = await fs.stat(reportPath);
  assert.equal(stat.mode & 0o777, 0o600);
  const serialized = await fs.readFile(reportPath, "utf8");
  for (const forbidden of [
    "example.invalid", "12345678901230", "+5511000000001",
    "synthetic note without legacy fields", "synthetic-audit.myshopify.com",
  ]) assert.equal(serialized.includes(forbidden), false);
  assert.match(serialized, /gid:\/\/shopify\/Customer\/synthetic-001/);

  const summary = JSON.stringify(auditSummary(report));
  assert.equal(summary.includes("customer_ids"), false);
  assert.equal(summary.includes("gid://"), false);
  assert.deepEqual(Object.keys(JSON.parse(summary)).sort(), ["categories", "totals"]);
});

test("legacy note parser accepts only the expected CNPJ and CEL structure", () => {
  assert.deepEqual(extractLegacyNote("CNPJ: 12.345.678/9012-30 | CEL: +55 11 00000-0001"), {
    cnpj: "12.345.678/9012-30",
    phone: "+55 11 00000-0001",
  });
  assert.equal(extractLegacyNote("synthetic free-form note"), null);
});
