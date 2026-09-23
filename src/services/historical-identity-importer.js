import crypto from "node:crypto";
import { persistedErrorRecord } from "../security.js";
import { readOnlyTelemetrySummary } from "../audit/read-only-telemetry.js";
import {
  buildHistoricalCustomerIdentityRecord,
  IDENTITY_IMPORT_CONFIRMATION,
  identityIndexSecretFingerprint,
  validateIdentityIndexSecret,
} from "../identity/historical-identities.js";

export class HistoricalIdentityImporter {
  constructor({
    store,
    shopDomain,
    identityIndexSecret,
    registrationIdentitySecret = "",
    clock = () => new Date(),
    runIdFactory = () => crypto.randomUUID(),
    logger = { info() {}, warn() {}, error() {} },
    telemetry,
    durationClock = () => performance.now(),
  }) {
    this.store = store;
    this.shopDomain = shopDomain;
    this.identityIndexSecret = validateIdentityIndexSecret(identityIndexSecret);
    this.registrationIdentitySecret = registrationIdentitySecret;
    this.secretFingerprint = identityIndexSecretFingerprint(identityIndexSecret);
    this.clock = clock;
    this.runIdFactory = runIdFactory;
    this.logger = logger;
    this.telemetry = telemetry;
    this.durationClock = durationClock;
  }

  async run({ pages, dryRun = true, confirmation = "" }) {
    if (!pages || typeof pages[Symbol.asyncIterator] !== "function") {
      throw new Error("identity_import_pages_required");
    }
    if (!dryRun && confirmation !== IDENTITY_IMPORT_CONFIRMATION) {
      throw new Error("identity_import_confirmation_required");
    }
    const runId = this.runIdFactory();
    const startedAt = this.durationClock();
    const claimCustomers = Object.fromEntries(["email", "cnpj", "phone"].map((type) => [type, new Map()]));
    const summary = {
      dry_run: Boolean(dryRun),
      pages_scanned: 0,
      customers_scanned: 0,
      claims_processed: 0,
      states_processed: 0,
      valid_customers: 0,
      invalid_or_incomplete_states: 0,
      identity_states: Object.fromEntries(["email", "cnpj", "phone"].map((type) => [type, {
        valid: 0, invalid: 0, incomplete: 0,
      }])),
      claims: Object.fromEntries(["email", "cnpj", "phone"].map((type) => [type, {
        active: 0, conflicted: 0, duplicate_groups: 0, members: 0,
      }])),
      duration_ms: 0,
      retries_total: 0,
      errors_by_category: {},
    };
    let started = false;
    try {
      if (!dryRun) {
        await this.store.beginHistoricalIdentityImport({
          runId,
          shopDomain: this.shopDomain,
          secretFingerprint: this.secretFingerprint,
          now: this.clock(),
        });
        started = true;
      }
      for await (const page of pages) {
        if (!Array.isArray(page)) throw new Error("identity_import_page_invalid");
        const customers = page.map((customer) => buildHistoricalCustomerIdentityRecord(
          customer,
          this.identityIndexSecret,
          this.registrationIdentitySecret,
        ));
        summary.pages_scanned += 1;
        summary.customers_scanned += customers.length;
        summary.claims_processed += customers.reduce((total, customer) => total + customer.claims.length, 0);
        summary.states_processed += customers.reduce((total, customer) => total + customer.states.length, 0);
        summary.valid_customers += customers.filter((customer) => customer.claims.length > 0).length;
        summary.invalid_or_incomplete_states += customers.reduce((total, customer) => (
          total + customer.states.filter((state) => state.validity !== "valid").length
        ), 0);
        for (const customer of customers) {
          for (const state of customer.states) summary.identity_states[state.type][state.validity] += 1;
          for (const claim of customer.claims) {
            const customersForClaim = claimCustomers[claim.type].get(claim.valueHash) || new Set();
            customersForClaim.add(customer.customerId);
            claimCustomers[claim.type].set(claim.valueHash, customersForClaim);
          }
        }
        if (!dryRun && customers.length) {
          await this.store.importHistoricalIdentityPage({
            runId,
            shopDomain: this.shopDomain,
            secretFingerprint: this.secretFingerprint,
            customers,
            now: this.clock(),
          });
        }
      }
      if (!dryRun) {
        await this.store.completeHistoricalIdentityImport({
          runId,
          shopDomain: this.shopDomain,
          secretFingerprint: this.secretFingerprint,
          identityIndexSecret: this.identityIndexSecret,
          summary,
          now: this.clock(),
        });
      }
      for (const type of ["email", "cnpj", "phone"]) {
        const memberships = [...claimCustomers[type].values()];
        summary.claims[type].active = memberships.filter((customers) => customers.size === 1).length;
        summary.claims[type].conflicted = memberships.filter((customers) => customers.size > 1).length;
        summary.claims[type].duplicate_groups = summary.claims[type].conflicted;
        summary.claims[type].members = memberships.reduce((total, customers) => total + customers.size, 0);
      }
      Object.assign(summary, readOnlyTelemetrySummary(this.telemetry));
      summary.duration_ms = Math.max(0, Math.round(this.durationClock() - startedAt));
      this.logger.info("historical_identity_import_completed", { durationMs: summary.duration_ms });
      return summary;
    } catch (error) {
      if (!dryRun && started) {
        const persistedError = persistedErrorRecord(error, { defaultCategory: "historical_identity" });
        await this.store.failHistoricalIdentityImport({
          runId,
          error: persistedError,
          now: this.clock(),
        }).catch(() => {});
      }
      const safeError = persistedErrorRecord(error, { defaultCategory: "historical_identity" });
      this.logger.error("historical_identity_import_failed", { code: safeError.code, category: safeError.category });
      throw error;
    }
  }
}
