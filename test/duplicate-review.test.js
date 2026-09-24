import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { buildDuplicateReview, duplicateReviewSummary } from "../src/audit/duplicate-review.js";
import { writeCustomerAuditReport } from "../src/audit/report.js";

const customer = (id, { cnpj, phone, emailValid = true, status = "approved", approved = true } = {}) => ({
  customer_id: `gid://shopify/Customer/${id}`,
  email: { present: true, valid: emailValid },
  cnpj_sources: [
    cnpj ? { source: "custom.cnpj", state: "valid", fingerprint: cnpj } : { source: "custom.cnpj", state: "absent" },
    { source: "custom.cjnpj", state: "absent" },
    { source: "note", state: "absent" },
  ],
  phone: {
    state: phone ? "official" : "absent",
    official: phone ? { state: "valid", fingerprint: phone } : { state: "absent" },
    note: { state: "absent" },
  },
  cnpj_status: status,
  has_b2b_approved: approved,
  has_b2b_pending: false,
});

const indicators = [
  customer("A", { cnpj: "cnpj-1", phone: "phone-1" }),
  customer("B", { cnpj: "cnpj-1", phone: "phone-1" }),
  customer("C", { cnpj: "cnpj-2", phone: "phone-2" }),
  customer("D", { cnpj: "cnpj-2", phone: "phone-3", emailValid: false }),
  customer("E", { cnpj: "cnpj-3", phone: "phone-4" }),
  customer("F", { cnpj: "cnpj-4", phone: "phone-4" }),
  customer("G", { cnpj: "cnpj-5", phone: "phone-5" }),
  customer("H", { cnpj: "cnpj-5", phone: "phone-6" }),
  customer("I", { cnpj: "cnpj-6", phone: "phone-6", status: "pending", approved: false }),
];

const ids = (...suffixes) => suffixes.map((suffix) => `gid://shopify/Customer/${suffix}`);

const syntheticAudit = {
  generated_at: "2030-01-01T00:00:00.000Z",
  source: { shop_domain_hash: "shop-hash", api_version: "2026-07", access: "read_only_graphql" },
  totals: { pages_scanned: 1, customers_scanned: indicators.length, findings: 0, affected_customers: indicators.length },
  customer_indicators: indicators,
  findings: {
    duplicate_cnpjs: [
      { value_hash: "cnpj-1", customer_ids: ids("A", "B") },
      { value_hash: "cnpj-2", customer_ids: ids("C", "D") },
      { value_hash: "cnpj-5", customer_ids: ids("G", "H") },
    ],
    duplicate_phones: [
      { value_hash: "phone-1", customer_ids: ids("A", "B") },
      { value_hash: "phone-4", customer_ids: ids("E", "F") },
      { value_hash: "phone-6", customer_ids: ids("H", "I") },
    ],
  },
};

test("classifies duplicate components and calculates overlap without double counting", () => {
  const review = buildDuplicateReview(syntheticAudit);
  assert.deepEqual(review.summary.totals, {
    cnpj_duplicate_groups: 3,
    phone_duplicate_groups: 3,
    connected_components: 4,
    customers_involved: 9,
    customers_in_both_duplicate_types: 3,
    components_with_invalid_or_incomplete_data: 1,
  });
  assert.deepEqual(review.summary.distributions, {
    cnpj_groups: { "2": 3, "3": 0, "4_or_more": 0 },
    phone_groups: { "2": 3, "3": 0, "4_or_more": 0 },
    connected_components: { "2": 3, "3": 1, "4_or_more": 0 },
  });
  assert.deepEqual(review.summary.classifications, {
    same_cnpj_same_phone: 1,
    same_cnpj_different_phones: 1,
    same_phone_different_cnpjs: 1,
    complex_transitive: 1,
  });
  assert.deepEqual(review.summary.overlap, {
    cnpj_only_customers: 3,
    phone_only_customers: 3,
    both_customer_types: 3,
  });
  assert.deepEqual(review.summary.theoretical_merges, {
    cnpj_groups_sum: 3,
    phone_groups_sum: 3,
    connected_components_deduplicated: 5,
  });
});

test("includes only pseudonymous associations and consistency flags", () => {
  const review = buildDuplicateReview(syntheticAudit);
  const sameBoth = review.connected_components.find((component) => component.classification === "same_cnpj_same_phone");
  assert.equal(sameBoth.customer_count, 2);
  assert.equal(sameBoth.theoretical_merges, 1);
  const cnpjGroup = review.cnpj_duplicate_groups.find((group) => group.cnpj_fingerprint === "cnpj-1");
  assert.equal(cnpjGroup.has_shared_phone, true);
  assert.equal(cnpjGroup.all_customers_share_same_phone, true);
  assert.equal(cnpjGroup.consistency.status_tag_aligned, true);
  const transitive = review.connected_components.find((component) => component.classification === "complex_transitive");
  assert.equal(transitive.customer_count, 3);
  assert.equal(transitive.consistency.cnpj_status_consistent, false);
  assert.equal(transitive.consistency.b2b_approved_consistent, false);
  assert.deepEqual(duplicateReviewSummary(review), review.summary);
});

test("buckets groups of four or more and calculates size minus one", () => {
  const fourCustomers = ["J", "K", "L", "M"].map((id, index) => customer(id, {
    cnpj: "cnpj-large",
    phone: `phone-unique-${index}`,
  }));
  const review = buildDuplicateReview({
    ...syntheticAudit,
    customer_indicators: fourCustomers,
    findings: {
      duplicate_cnpjs: [{ value_hash: "cnpj-large", customer_ids: ids("J", "K", "L", "M") }],
      duplicate_phones: [],
    },
  });
  assert.deepEqual(review.summary.distributions.cnpj_groups, { "2": 0, "3": 0, "4_or_more": 1 });
  assert.deepEqual(review.summary.distributions.connected_components, { "2": 0, "3": 0, "4_or_more": 1 });
  assert.equal(review.cnpj_duplicate_groups[0].theoretical_merges, 3);
  assert.equal(review.summary.theoretical_merges.connected_components_deduplicated, 3);
});

test("writes the duplicate review with private permissions and no raw PII", async (t) => {
  const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "b2b-duplicate-review-"));
  t.after(() => fs.rm(temporaryRoot, { recursive: true, force: true }));
  const reportPath = await writeCustomerAuditReport(buildDuplicateReview(syntheticAudit), { cwd: temporaryRoot });
  assert.match(path.basename(reportPath), /^duplicate-review-/);
  const stat = await fs.stat(reportPath);
  assert.equal(stat.mode & 0o777, 0o600);
  const serialized = await fs.readFile(reportPath, "utf8");
  assert.doesNotMatch(serialized, /@|\+55|\d{14}/);
});
