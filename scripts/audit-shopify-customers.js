import fetch from "node-fetch";
import { auditShopifyCustomers, auditSummary } from "../src/audit/customer-audit.js";
import { loadCustomerAuditConfig } from "../src/audit/config.js";
import { buildDuplicateReview, duplicateReviewSummary } from "../src/audit/duplicate-review.js";
import { writeCustomerAuditReport } from "../src/audit/report.js";
import { ReadOnlyShopifyCustomerClient } from "../src/audit/shopify-customer-client.js";
import { createLogger } from "../src/logger.js";

const safeLogger = createLogger({
  log: () => {},
  warn: (line) => process.stderr.write(`${line}\n`),
  error: (line) => process.stderr.write(`${line}\n`),
});

try {
  const config = loadCustomerAuditConfig(process.env);
  const client = new ReadOnlyShopifyCustomerClient({
    fetchImpl: fetch,
    shopDomain: config.shopDomain,
    token: config.token,
    apiVersion: config.apiVersion,
    timeoutMs: config.timeoutMs,
    maxRetries: config.maxRetries,
    logger: safeLogger,
  });
  const report = await auditShopifyCustomers({
    client,
    shopDomain: config.shopDomain,
    apiVersion: config.apiVersion,
  });
  const review = buildDuplicateReview(report);
  await writeCustomerAuditReport(review);
  process.stdout.write(`${JSON.stringify({
    audit: auditSummary(report),
    duplicate_review: duplicateReviewSummary(review),
  }, null, 2)}\n`);
} catch (error) {
  const knownCodes = new Set([
    "audit_confirmation_required", "audit_read_only_mode_required", "audit_shop_confirmation_mismatch",
    "invalid_audit_shop_domain", "audit_shopify_token_required", "invalid_audit_api_version",
    "invalid_audit_configuration", "shopify_audit_unavailable", "shopify_audit_query_failed",
    "shopify_audit_pagination_failed", "invalid_shopify_customer_id",
  ]);
  const candidate = error?.code || error?.message;
  safeLogger.error("shopify_customer_audit_failed", { code: knownCodes.has(candidate) ? candidate : "internal_error" });
  process.exitCode = 1;
}
