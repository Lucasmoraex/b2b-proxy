import crypto from "node:crypto";
import { persistedErrorRecord } from "./security.js";
import { decryptRegistrationOperationalPayload } from "./pii-crypto.js";
import { normalizeEmployeeRange } from "./validation.js";

const metafield = (key, value, type = "single_line_text_field") => ({ key, value: String(value), type });

export class OutboxWorker {
  constructor({
    store, shopifyClient, clock = () => new Date(), logger, piiKeyring,
    syncedPayloadRetentionMs = 7 * 24 * 60 * 60 * 1000,
    autoApprove = false, maxAttempts = 8, workerId = crypto.randomUUID(),
  }) {
    this.store = store;
    this.shopify = shopifyClient;
    this.clock = clock;
    this.logger = logger;
    this.piiKeyring = piiKeyring;
    this.syncedPayloadRetentionMs = syncedPayloadRetentionMs;
    this.autoApprove = autoApprove;
    this.maxAttempts = maxAttempts;
    this.workerId = workerId;
  }

  async runOnce() {
    const now = this.clock();
    const item = await this.store.claimOutbox({ workerId: this.workerId, now });
    if (!item) return false;
    try {
      await this.process(item);
      return true;
    } catch (error) {
      const attempts = item.attempts + 1;
      const persistedError = persistedErrorRecord(error, { defaultCategory: "shopify" });
      const terminal = persistedError.code === "payload_purged" || attempts >= this.maxAttempts;
      const delayMs = Math.min(60 * 60 * 1000, 1000 * (2 ** attempts));
      await this.store.failOutbox({ item, error: persistedError, now: this.clock(), nextAttemptAt: new Date(this.clock().getTime() + delayMs), terminal });
      this.logger.warn("outbox_retry", {
        operation: item.operation,
        attempts,
        terminal,
        code: persistedError.code,
        category: persistedError.category,
      });
      return true;
    }
  }

  async process(item) {
    const registration = item.registration;
    if (!registration?.shopify_customer_id) throw Object.assign(new Error("missing customer binding"), { code: "missing_customer_binding" });
    switch (item.operation) {
      case "sync_registration": return this.sync(item, registration);
      case "approve_registration": return this.approve(item, registration);
      case "reject_registration": return this.reject(item, registration);
      case "reconcile_registration": return this.reconcile(item, registration);
      default: throw Object.assign(new Error("unknown operation"), { code: "unknown_operation" });
    }
  }

  async withOperationalPayload(registration) {
    const encrypted = await this.store.getOperationalPayload(registration.id);
    if (encrypted && !encrypted.purged_at) {
      try {
        const payload = decryptRegistrationOperationalPayload({
          registrationId: registration.id,
          encrypted,
          keyring: this.piiKeyring,
        });
        const employeeRange = payload.employee_range === undefined
          ? null
          : normalizeEmployeeRange(payload.employee_range);
        if (registration.employee_range_required && !employeeRange) throw new Error("employee range unavailable");
        return {
          ...registration,
          email_normalized: payload.email,
          cnpj_normalized: payload.cnpj,
          phone_e164: payload.phone,
          employee_range: employeeRange,
        };
      } catch (error) {
        throw Object.assign(new Error("operational payload unavailable"), {
          code: error?.message === "payload_purged" ? "payload_purged" : "payload_unavailable",
        });
      }
    }
    if (registration.email_normalized && registration.cnpj_normalized && registration.phone_e164) {
      return registration;
    }
    throw Object.assign(new Error("operational payload purged"), { code: "payload_purged" });
  }

  async sync(item, registration) {
    registration = await this.withOperationalPayload(registration);
    await this.shopify.updatePhone(registration.shopify_customer_id, registration.phone_e164);
    const fields = [
      metafield("cnpj", registration.cnpj_normalized),
      metafield("cnpj_status", "pending"),
      metafield("cnpj_exists", "true", "boolean"),
      metafield("cnpj_situacao", registration.fiscal_status),
      metafield("cnpj_checked_at", new Date(registration.fiscal_validated_at).toISOString(), "date_time"),
    ];
    if (registration.employee_range) fields.push(metafield("employee_range", registration.employee_range));
    await this.shopify.setMetafields(registration.shopify_customer_id, fields);
    await this.shopify.removeTags(registration.shopify_customer_id, ["b2b-approved"]);
    await this.shopify.addTags(registration.shopify_customer_id, ["b2b-pending"]);
    const completedAt = this.clock();
    await this.store.completeOutbox({
      item, registrationStatus: "pending_review", syncCompleted: true, now: completedAt,
      payloadNeededUntil: new Date(completedAt.getTime() + this.syncedPayloadRetentionMs),
      enqueueApprove: this.autoApprove,
    });
  }

  async approve(item, registration) {
    if (!registration.sync_completed_at || registration.fiscal_status !== "ATIVA") throw Object.assign(new Error("registration not ready"), { code: "registration_not_ready" });
    await this.shopify.removeTags(registration.shopify_customer_id, ["b2b-pending"]);
    await this.shopify.addTags(registration.shopify_customer_id, ["b2b-approved"]);
    // cnpj_status is written last: the theme must require both status and tag.
    await this.shopify.setMetafields(registration.shopify_customer_id, [metafield("cnpj_status", "approved")]);
    await this.store.completeOutbox({ item, registrationStatus: "approved", now: this.clock() });
  }

  async reject(item, registration) {
    await this.shopify.removeTags(registration.shopify_customer_id, ["b2b-approved", "b2b-pending"]);
    await this.shopify.setMetafields(registration.shopify_customer_id, [metafield("cnpj_status", "rejected")]);
    await this.store.completeOutbox({ item, registrationStatus: "rejected", now: this.clock() });
  }

  async reconcile(item, registration) {
    if (registration.status !== "rejected") registration = await this.withOperationalPayload(registration);
    const customer = await this.shopify.getCustomerState(registration.shopify_customer_id);
    if (!customer) throw Object.assign(new Error("customer unavailable"), { code: "shopify_customer_not_found" });
    if (registration.status === "approved") {
      const fields = [metafield("cnpj", registration.cnpj_normalized), metafield("cnpj_status", "approved")];
      if (registration.employee_range) fields.push(metafield("employee_range", registration.employee_range));
      await this.shopify.setMetafields(registration.shopify_customer_id, fields);
      await this.shopify.updatePhone(registration.shopify_customer_id, registration.phone_e164);
      await this.shopify.addTags(registration.shopify_customer_id, ["b2b-approved"]);
      await this.shopify.removeTags(registration.shopify_customer_id, ["b2b-pending"]);
      await this.store.completeOutbox({ item, registrationStatus: "approved", now: this.clock() });
    } else if (registration.status === "rejected") {
      await this.reject(item, registration);
    } else {
      await this.sync(item, registration);
    }
  }
}
