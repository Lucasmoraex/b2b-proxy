import crypto from "node:crypto";
import { AppError } from "../errors.js";

export class MemoryRegistrationStore {
  constructor({ clock = () => new Date(), idFactory = () => crypto.randomUUID() } = {}) {
    this.clock = clock;
    this.idFactory = idFactory;
    this.registrations = new Map();
    this.webhooks = new Map();
    this.outbox = new Map();
    this.lock = Promise.resolve();
  }

  atomic(fn) {
    const result = this.lock.then(fn, fn);
    this.lock = result.catch(() => {});
    return result;
  }

  clone(value) { return value ? structuredClone(value) : value; }

  async reserve(input) {
    return this.atomic(() => {
      const byKey = [...this.registrations.values()].find((r) => r.idempotency_key === input.idempotencyKey);
      if (byKey && new Date(byKey.expires_at) > input.now) {
        if (byKey.request_digest !== input.requestDigest) throw new AppError("idempotency_conflict", 409);
        return { registration: this.clone(byKey), reused: true };
      }
      if (byKey?.shopify_customer_id) throw new AppError("idempotency_conflict", 409);
      for (const [id, registration] of this.registrations) {
        if (new Date(registration.expires_at) <= input.now && !registration.shopify_customer_id && ["reserved", "pending_shopify", "expired"].includes(registration.status)) {
          this.registrations.delete(id);
          for (const [outboxId, item] of this.outbox) if (item.registration_id === id) this.outbox.delete(outboxId);
        }
      }
      const constraints = [
        ["email_normalized", input.email, "email_in_use"],
        ["cnpj_normalized", input.cnpj, "cnpj_in_use"],
        ["phone_e164", input.phone, "phone_in_use"],
        ["idempotency_key", input.idempotencyKey, "idempotency_conflict"],
      ];
      for (const [field, value, code] of constraints) {
        if ([...this.registrations.values()].some((r) => r[field] === value)) throw new AppError(code, 409);
      }
      const registration = {
        id: this.idFactory(), email_normalized: input.email, cnpj_normalized: input.cnpj,
        phone_e164: input.phone, shopify_customer_id: null, status: "reserved",
        idempotency_key: input.idempotencyKey, request_digest: input.requestDigest,
        fiscal_status: input.fiscalStatus, fiscal_validated_at: input.now,
        sync_completed_at: null, expires_at: input.expiresAt,
        created_at: input.now, updated_at: input.now,
      };
      this.registrations.set(registration.id, registration);
      return { registration: this.clone(registration), reused: false };
    });
  }

  async findByIdempotencyKey(idempotencyKey) {
    return this.clone([...this.registrations.values()].find((r) => r.idempotency_key === idempotencyKey) || null);
  }

  addOutbox(registrationId, operation, now) {
    const existing = [...this.outbox.values()].find((i) => i.registration_id === registrationId && i.operation === operation && !i.processed_at);
    if (existing) return existing;
    const item = { id: this.idFactory(), registration_id: registrationId, operation, attempts: 0, next_attempt_at: now, processed_at: null, last_error: null, locked_at: null, created_at: now };
    this.outbox.set(item.id, item);
    return item;
  }

  async associateWebhook({ eventId, topic, payloadDigest, email, customerId, now }) {
    return this.atomic(() => {
      if (this.webhooks.has(eventId)) return { duplicate: true };
      this.webhooks.set(eventId, { event_id: eventId, topic, payload_digest: payloadDigest, processed_at: now });
      const registration = [...this.registrations.values()].find((r) => r.email_normalized === email && new Date(r.expires_at) > now && ["reserved", "pending_shopify", "pending_validation"].includes(r.status));
      if (!registration) return { duplicate: false, found: false };
      if (registration.shopify_customer_id && registration.shopify_customer_id !== customerId) {
        registration.status = "failed";
        return { duplicate: false, found: true, conflict: true };
      }
      if ([...this.registrations.values()].some((r) => r.id !== registration.id && r.shopify_customer_id === customerId)) {
        registration.status = "failed";
        return { duplicate: false, found: true, conflict: true };
      }
      registration.shopify_customer_id = customerId;
      registration.status = "pending_validation";
      registration.updated_at = now;
      this.addOutbox(registration.id, "sync_registration", now);
      return { duplicate: false, found: true, registration: this.clone(registration) };
    });
  }

  async requestAdminOperation({ action, registrationId, customerId, now }) {
    return this.atomic(() => {
      const registration = [...this.registrations.values()].find((r) => (registrationId && r.id === registrationId) || (customerId && r.shopify_customer_id === customerId));
      if (!registration) throw new AppError("registration_not_found", 404);
      if (action === "approve") {
        if (registration.status === "approved") return { registration: this.clone(registration), idempotent: true };
        if (!registration.cnpj_normalized) throw new AppError("missing_cnpj", 409);
        if (registration.fiscal_status !== "ATIVA") throw new AppError("cnpj_not_validated", 409);
        if (!registration.shopify_customer_id || !registration.sync_completed_at || registration.status !== "pending_review") throw new AppError("registration_not_ready", 409);
        this.addOutbox(registration.id, "approve_registration", now);
      } else {
        if (registration.status === "rejected") return { registration: this.clone(registration), idempotent: true };
        if (!registration.shopify_customer_id) {
          registration.status = "rejected";
          registration.updated_at = now;
          return { registration: this.clone(registration), completed: true };
        }
        this.addOutbox(registration.id, "reject_registration", now);
      }
      return { registration: this.clone(registration), idempotent: false, completed: false };
    });
  }

  async claimOutbox({ workerId, now }) {
    return this.atomic(() => {
      const item = [...this.outbox.values()].sort((a, b) => new Date(a.next_attempt_at) - new Date(b.next_attempt_at))
        .find((i) => !i.processed_at && new Date(i.next_attempt_at) <= now && (!i.locked_at || new Date(i.locked_at) < new Date(now.getTime() - 300000)));
      if (!item) return null;
      item.locked_at = now; item.locked_by = workerId;
      return { ...this.clone(item), registration: this.clone(this.registrations.get(item.registration_id)) };
    });
  }

  async completeOutbox({ item, registrationStatus, syncCompleted = false, now, enqueueApprove = false }) {
    return this.atomic(() => {
      const stored = this.outbox.get(item.id); stored.processed_at = now; stored.locked_at = null; stored.last_error = null;
      const registration = this.registrations.get(item.registration_id);
      registration.status = registrationStatus; registration.updated_at = now;
      if (syncCompleted) registration.sync_completed_at = now;
      if (enqueueApprove) this.addOutbox(registration.id, "approve_registration", now);
      return this.clone(registration);
    });
  }

  async failOutbox({ item, error, now, nextAttemptAt, terminal }) {
    return this.atomic(() => {
      const stored = this.outbox.get(item.id); stored.attempts += 1; stored.last_error = error; stored.next_attempt_at = nextAttemptAt; stored.locked_at = null;
      if (terminal) { stored.processed_at = now; this.registrations.get(item.registration_id).status = "failed"; }
    });
  }

  async enqueueReconciliation(registrationId) {
    return this.atomic(() => {
      if (!this.registrations.has(registrationId)) throw new AppError("registration_not_found", 404);
      this.addOutbox(registrationId, "reconcile_registration", this.clock());
    });
  }

  async getRegistration(id) { return this.clone(this.registrations.get(id) || null); }
  async close() {}
}
