import crypto from "node:crypto";
import { AppError } from "../errors.js";
import { registrationIdentityClaims } from "../identity/historical-identities.js";

export class MemoryRegistrationStore {
  constructor({ clock = () => new Date(), idFactory = () => crypto.randomUUID() } = {}) {
    this.clock = clock;
    this.idFactory = idFactory;
    this.registrations = new Map();
    this.webhooks = new Map();
    this.outbox = new Map();
    this.fiscalCache = new Map();
    this.simulationCustomers = new Map();
    this.historicalIdentityMetadata = new Map();
    this.historicalIdentityRuns = new Map();
    this.historicalIdentityStates = new Map();
    this.historicalIdentityMembers = new Map();
    this.rateLimitBuckets = new Map();
    this.registrationAdmissions = new Map();
    this.registrationIdentityClaims = new Map();
    this.operationalPayloads = new Map();
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
      if (byKey && (byKey.shopify_customer_id || new Date(byKey.expires_at) > input.now)) {
        if (byKey.request_digest_version !== input.requestDigestVersion
          || byKey.request_digest !== input.requestDigest) throw new AppError("idempotency_conflict", 409);
        return { registration: this.clone(byKey), reused: true };
      }
      if (byKey?.shopify_customer_id) throw new AppError("idempotency_conflict", 409);
      if (input.historicalIdentity) {
        const activeRunId = this.assertActiveHistoricalSnapshot(
          input.historicalIdentity.shopDomain,
          input.historicalIdentity.secretFingerprint,
        );
        const conflict = this.historicalConflict(
          input.historicalIdentity.shopDomain,
          input.historicalIdentity.claims,
          activeRunId,
        );
        if (conflict) throw new AppError(conflict, 409);
      }
      for (const registration of this.registrations.values()) {
        if (new Date(registration.expires_at) <= input.now && !registration.shopify_customer_id && ["reserved", "pending_shopify", "expired"].includes(registration.status)) {
          registration.status = "expired";
          registration.updated_at = input.now;
          registration.email_normalized = null;
          registration.cnpj_normalized = null;
          registration.phone_e164 = null;
          for (const claim of this.registrationIdentityClaims.values()) {
            if (claim.registration_id === registration.id && claim.claim_state === "reserved") {
              claim.claim_state = "released";
              claim.released_at = input.now;
            }
          }
        }
      }
      if (input.requestIpHash && input.activeReservationsMax) {
        const activeForIp = [...this.registrations.values()].filter((registration) => (
          registration.request_ip_hash === input.requestIpHash
          && !registration.shopify_customer_id
          && new Date(registration.expires_at) > input.now
          && ["reserved", "pending_shopify", "pending_validation", "pending_review"].includes(registration.status)
        )).length;
        if (activeForIp >= input.activeReservationsMax) throw new AppError("rate_limited", 429);
      }
      const claimConflict = this.registrationClaimConflict(input.registrationClaims || [], input.now);
      if (claimConflict) throw new AppError(claimConflict, 409);
      const constraints = [
        ["email_normalized", input.email, "email_in_use"],
        ["cnpj_normalized", input.cnpj, "cnpj_in_use"],
        ["phone_e164", input.phone, "phone_in_use"],
        ["idempotency_key", input.idempotencyKey, "idempotency_conflict"],
      ];
      for (const [field, value, code] of constraints) {
        if ([...this.registrations.values()].some((registration) => {
          if (field === "idempotency_key") return registration[field] === value;
          const expiredUnlinked = new Date(registration.expires_at) <= input.now
            && !registration.shopify_customer_id
            && ["reserved", "pending_shopify", "expired"].includes(registration.status);
          return !expiredUnlinked && registration[field] === value;
        })) throw new AppError(code, 409);
      }
      const minimized = Boolean(input.operationalPayload && input.registrationClaims?.length === 3);
      const registration = {
        id: input.registrationId || this.idFactory(),
        email_normalized: minimized ? null : input.email,
        cnpj_normalized: minimized ? null : input.cnpj,
        phone_e164: minimized ? null : input.phone,
        shopify_customer_id: null, status: "reserved",
        idempotency_key: input.idempotencyKey, request_digest: input.requestDigest,
        request_digest_version: input.requestDigestVersion,
        fiscal_status: input.fiscalStatus, fiscal_validated_at: input.now,
        sync_completed_at: null, expires_at: input.expiresAt,
        request_ip_hash: input.requestIpHash || null,
        created_at: input.now, updated_at: input.now,
      };
      this.registrations.set(registration.id, registration);
      for (const claim of input.registrationClaims || []) {
        const key = `${registration.id}\0${claim.type}\0${claim.keyVersion}`;
        this.registrationIdentityClaims.set(key, {
          registration_id: registration.id,
          identity_type: claim.type,
          key_version: claim.keyVersion,
          value_hash: claim.valueHash,
          claim_state: "reserved",
          created_at: input.now,
          activated_at: null,
          released_at: null,
        });
      }
      if (input.operationalPayload) {
        this.operationalPayloads.set(registration.id, {
          registration_id: registration.id,
          ciphertext: Buffer.from(input.operationalPayload.ciphertext),
          nonce: Buffer.from(input.operationalPayload.nonce),
          auth_tag: Buffer.from(input.operationalPayload.authTag),
          encryption_key_version: input.operationalPayload.encryptionKeyVersion,
          needed_until: input.operationalPayload.neededUntil,
          created_at: input.now,
          purged_at: null,
        });
      }
      return { registration: this.clone(registration), reused: false };
    });
  }

  async findByIdempotencyKey(idempotencyKey) {
    return this.clone([...this.registrations.values()].find((r) => r.idempotency_key === idempotencyKey) || null);
  }

  async consumeRegistrationQuota(input) {
    return this.atomic(() => {
      const nowMs = input.now.getTime();
      for (const [key, bucket] of this.rateLimitBuckets) {
        if (new Date(bucket.expires_at).getTime() <= nowMs) this.rateLimitBuckets.delete(key);
      }
      for (const [key, admission] of this.registrationAdmissions) {
        if (new Date(admission.expires_at).getTime() <= nowMs) this.registrationAdmissions.delete(key);
      }

      const previous = this.registrationAdmissions.get(input.idempotencyKey);
      if (previous) {
        if (previous.request_key_digest_version !== input.requestKeyDigestVersion
          || previous.request_key_digest !== input.requestKeyDigest) throw new AppError("idempotency_conflict", 409);
        return { reused: true };
      }

      const activeForIp = [...this.registrations.values()].filter((registration) => (
        registration.request_ip_hash === input.ipHash
        && !registration.shopify_customer_id
        && new Date(registration.expires_at) > input.now
        && ["reserved", "pending_shopify", "pending_validation", "pending_review"].includes(registration.status)
      )).length;
      if (activeForIp >= input.activeReservationsMax) throw new AppError("rate_limited", 429);

      const buckets = [
        { scope: "registration_ip", keyHash: input.ipHash, windowMs: input.sharedWindowMs, max: input.sharedMax },
        ...input.identityKeys.map((identity) => ({
          scope: `registration_identity_${identity.type}`,
          keyHash: identity.keyHash,
          windowMs: input.identityWindowMs,
          max: input.identityMax,
        })),
      ];
      const updates = buckets.map((bucket) => {
        const windowStartedAt = new Date(Math.floor(nowMs / bucket.windowMs) * bucket.windowMs);
        const key = `${bucket.scope}\0${bucket.keyHash}\0${windowStartedAt.toISOString()}`;
        const existing = this.rateLimitBuckets.get(key);
        const hitCount = (existing?.hit_count || 0) + 1;
        if (hitCount > bucket.max) throw new AppError("rate_limited", 429);
        return {
          key,
          value: {
            scope: bucket.scope,
            key_hash: bucket.keyHash,
            window_started_at: windowStartedAt,
            hit_count: hitCount,
            expires_at: new Date(windowStartedAt.getTime() + bucket.windowMs + input.stateRetentionMs),
            updated_at: input.now,
          },
        };
      });
      for (const update of updates) this.rateLimitBuckets.set(update.key, update.value);
      this.registrationAdmissions.set(input.idempotencyKey, {
        idempotency_key: input.idempotencyKey,
        request_key_digest: input.requestKeyDigest,
        request_key_digest_version: input.requestKeyDigestVersion,
        ip_key_hash: input.ipHash,
        admitted_at: input.now,
        expires_at: new Date(nowMs + input.stateRetentionMs),
      });
      return { reused: false };
    });
  }

  async cleanupRegistrationAbuseState({ now }) {
    return this.atomic(() => {
      let buckets = 0;
      let admissions = 0;
      for (const [key, bucket] of this.rateLimitBuckets) {
        if (new Date(bucket.expires_at) <= now) {
          this.rateLimitBuckets.delete(key);
          buckets += 1;
        }
      }
      for (const [key, admission] of this.registrationAdmissions) {
        if (new Date(admission.expires_at) <= now) {
          this.registrationAdmissions.delete(key);
          admissions += 1;
        }
      }
      return { buckets, admissions };
    });
  }

  registrationClaimConflict(identityClaims, now) {
    const codes = { email: "email_in_use", cnpj: "cnpj_in_use", phone: "phone_in_use" };
    for (const type of ["email", "cnpj", "phone"]) {
      const candidate = identityClaims.find((claim) => claim.type === type);
      if (!candidate) continue;
      const blocked = [...this.registrationIdentityClaims.values()].some((claim) => {
        if (claim.identity_type !== type || claim.key_version !== candidate.keyVersion
          || claim.value_hash !== candidate.valueHash || claim.claim_state === "released") return false;
        const registration = this.registrations.get(claim.registration_id);
        return !(claim.claim_state === "reserved" && registration && !registration.shopify_customer_id
          && new Date(registration.expires_at) <= now);
      });
      if (blocked) return codes[type];
    }
    return null;
  }

  async findConflict({ email, cnpj, phone, identityClaims = [], now }) {
    const claimConflict = this.registrationClaimConflict(identityClaims, now);
    if (claimConflict) return claimConflict;
    const blocksReservation = (registration) => !(
      new Date(registration.expires_at) <= now
      && !registration.shopify_customer_id
      && ["reserved", "pending_shopify", "expired"].includes(registration.status)
    );
    const registrations = [...this.registrations.values()].filter(blocksReservation);
    if (registrations.some((registration) => registration.email_normalized === email)) return "email_in_use";
    if (registrations.some((registration) => registration.cnpj_normalized === cnpj)) return "cnpj_in_use";
    if (registrations.some((registration) => registration.phone_e164 === phone)) return "phone_in_use";
    return null;
  }

  assertHistoricalMetadata(shopDomain, secretFingerprint) {
    const metadata = this.historicalIdentityMetadata.get(shopDomain);
    if (metadata?.secret_fingerprint !== secretFingerprint) {
      throw new AppError("identity_index_unavailable", 503);
    }
    return metadata;
  }

  assertActiveHistoricalSnapshot(shopDomain, secretFingerprint) {
    const metadata = this.assertHistoricalMetadata(shopDomain, secretFingerprint);
    const run = metadata.active_import_run_id
      ? this.historicalIdentityRuns.get(metadata.active_import_run_id)
      : null;
    if (!run || run.shop_domain !== shopDomain || run.status !== "completed") {
      throw new AppError("identity_index_unavailable", 503);
    }
    return run.id;
  }

  historicalConflict(shopDomain, claims, activeRunId) {
    const codes = { email: "email_in_use", cnpj: "cnpj_in_use", phone: "phone_in_use" };
    for (const type of ["email", "cnpj", "phone"]) {
      const claim = claims.find((candidate) => candidate.type === type);
      if (!claim) continue;
      const found = [...this.historicalIdentityMembers.values()].some((member) => (
        member.import_run_id === activeRunId && member.shop_domain === shopDomain && member.identity_type === type
        && member.value_hash === claim.valueHash && member.validity === "valid"
      ));
      if (found) return codes[type];
    }
    return null;
  }

  async findHistoricalConflict({ shopDomain, claims, secretFingerprint }) {
    const activeRunId = this.assertActiveHistoricalSnapshot(shopDomain, secretFingerprint);
    return this.historicalConflict(shopDomain, claims, activeRunId);
  }

  async beginHistoricalIdentityImport({ runId, shopDomain, secretFingerprint, now }) {
    return this.atomic(() => {
      const metadata = this.historicalIdentityMetadata.get(shopDomain);
      if (metadata && metadata.secret_fingerprint !== secretFingerprint) {
        throw new Error("historical_identity_index_unavailable");
      }
      this.historicalIdentityMetadata.set(shopDomain, {
        shop_domain: shopDomain,
        secret_fingerprint: secretFingerprint,
        active_import_run_id: metadata?.active_import_run_id || null,
        created_at: metadata?.created_at || now,
        verified_at: now,
      });
      if (this.historicalIdentityRuns.has(runId)) throw new Error("historical_identity_import_run_exists");
      this.historicalIdentityRuns.set(runId, {
        id: runId, shop_domain: shopDomain, secret_fingerprint: secretFingerprint,
        status: "staging", started_at: now,
      });
    });
  }

  async importHistoricalIdentityPage({ runId, shopDomain, secretFingerprint, customers, now }) {
    return this.atomic(() => {
      this.assertHistoricalMetadata(shopDomain, secretFingerprint);
      const run = this.historicalIdentityRuns.get(runId);
      if (run?.shop_domain !== shopDomain || run.status !== "staging") {
        throw new Error("historical_identity_import_not_staging");
      }
      for (const customer of customers) {
        for (const claim of customer.claims) {
          const fields = { email: "email_normalized", cnpj: "cnpj_normalized", phone: "phone_e164" };
          const field = fields[claim.type];
          const indexedConflict = claim.registrationValueHash && [...this.registrationIdentityClaims.values()]
            .some((identityClaim) => {
              if (identityClaim.identity_type !== claim.type
                || identityClaim.key_version !== claim.registrationKeyVersion
                || identityClaim.value_hash !== claim.registrationValueHash
                || identityClaim.claim_state === "released") return false;
              const registration = this.registrations.get(identityClaim.registration_id);
              const expiredReserved = identityClaim.claim_state === "reserved"
                && !registration?.shopify_customer_id && new Date(registration?.expires_at) <= now;
              return !expiredReserved && registration?.shopify_customer_id !== customer.customerId;
            });
          if (indexedConflict) throw new Error("historical_identity_registration_conflict");
          const conflict = [...this.registrations.values()].some((registration) => {
            const expiredUnbound = new Date(registration.expires_at) <= now
              && !registration.shopify_customer_id
              && ["reserved", "pending_shopify", "expired"].includes(registration.status);
            return !expiredUnbound && registration[field] === claim.normalized
              && registration.shopify_customer_id !== customer.customerId;
          });
          if (conflict) throw new Error("historical_identity_registration_conflict");
        }
      }
      for (const customer of customers) {
        for (const state of customer.states) {
          const key = `${runId}\0${shopDomain}\0${customer.customerId}\0${state.type}`;
          const previous = this.historicalIdentityStates.get(key);
          this.historicalIdentityStates.set(key, {
            import_run_id: runId, shop_domain: shopDomain, shopify_customer_id: customer.customerId,
            identity_type: state.type, validity: state.validity, sources: [...state.sources],
            imported_at: now,
          });
        }
        for (const claim of customer.claims) {
          const key = `${runId}\0${shopDomain}\0${customer.customerId}\0${claim.type}\0${claim.valueHash}`;
          const previous = this.historicalIdentityMembers.get(key);
          this.historicalIdentityMembers.set(key, {
            import_run_id: runId, shop_domain: shopDomain, shopify_customer_id: customer.customerId,
            identity_type: claim.type, value_hash: claim.valueHash, validity: "valid",
            registration_key_version: claim.registrationKeyVersion,
            registration_value_hash: claim.registrationValueHash,
            sources: [...new Set([...(previous?.sources || []), ...claim.sources])].sort(),
            imported_at: now,
          });
        }
      }
    });
  }

  async completeHistoricalIdentityImport({
    runId, shopDomain, secretFingerprint, identityIndexSecret, summary, now,
  }) {
    return this.atomic(() => {
      const metadata = this.assertHistoricalMetadata(shopDomain, secretFingerprint);
      const run = this.historicalIdentityRuns.get(runId);
      if (run?.shop_domain !== shopDomain || run.status !== "staging") {
        throw new Error("historical_identity_import_not_staging");
      }

      const pendingStates = new Map();
      const pendingMembers = new Map();
      const collectForRun = (collection, target, sourceRunId, isMember) => {
        for (const value of collection.values()) {
          if (value.import_run_id !== sourceRunId || value.shop_domain !== shopDomain) continue;
          const suffix = isMember
            ? `${value.shopify_customer_id}\0${value.identity_type}\0${value.value_hash}`
            : `${value.shopify_customer_id}\0${value.identity_type}`;
          target.set(suffix, { ...this.clone(value), import_run_id: runId, imported_at: now });
        }
      };
      if (metadata.active_import_run_id) {
        collectForRun(this.historicalIdentityStates, pendingStates, metadata.active_import_run_id, false);
        collectForRun(this.historicalIdentityMembers, pendingMembers, metadata.active_import_run_id, true);
      }
      collectForRun(this.historicalIdentityStates, pendingStates, runId, false);
      collectForRun(this.historicalIdentityMembers, pendingMembers, runId, true);

      const blocksReservation = (registration) => !(
        new Date(registration.expires_at) <= now
        && !registration.shopify_customer_id
        && ["reserved", "pending_shopify", "expired"].includes(registration.status)
      );
      for (const registration of [...this.registrations.values()].filter(blocksReservation)) {
        const indexedClaims = [...this.registrationIdentityClaims.values()].filter((claim) => (
          claim.registration_id === registration.id && claim.claim_state !== "released"
        ));
        for (const claim of indexedClaims) {
          const conflict = [...pendingMembers.values()].some((member) => (
            member.identity_type === claim.identity_type
            && member.registration_key_version === claim.key_version
            && member.registration_value_hash === claim.value_hash
            && member.shopify_customer_id !== registration.shopify_customer_id
          ));
          if (conflict) throw new Error("historical_identity_registration_conflict");
        }
        if (!(registration.email_normalized && registration.cnpj_normalized && registration.phone_e164)) continue;
        const claims = registrationIdentityClaims({
          email: registration.email_normalized,
          cnpj: registration.cnpj_normalized,
          phone: registration.phone_e164,
          secret: identityIndexSecret,
        });
        for (const claim of claims) {
          const conflict = [...pendingMembers.values()].some((member) => (
            member.identity_type === claim.type
            && member.value_hash === claim.valueHash
            && member.shopify_customer_id !== registration.shopify_customer_id
          ));
          if (conflict) throw new Error("historical_identity_registration_conflict");
        }
      }

      for (const [suffix, value] of pendingStates) {
        this.historicalIdentityStates.set(`${runId}\0${shopDomain}\0${suffix}`, value);
      }
      for (const [suffix, value] of pendingMembers) {
        this.historicalIdentityMembers.set(`${runId}\0${shopDomain}\0${suffix}`, value);
      }
      Object.assign(run, {
        status: "completed", completed_at: now, pages_scanned: summary.pages_scanned,
        customers_scanned: summary.customers_scanned, claims_processed: summary.claims_processed,
        states_processed: summary.states_processed, last_error: null,
        error_code: null, error_category: null, upstream_status: null, error_recorded_at: null,
      });
      metadata.active_import_run_id = runId;
      metadata.verified_at = now;
    });
  }

  async failHistoricalIdentityImport({ runId, error, now }) {
    return this.atomic(() => {
      const run = this.historicalIdentityRuns.get(runId);
      if (run?.status === "staging") Object.assign(run, {
        status: "failed",
        completed_at: now,
        last_error: null,
        error_code: error.code,
        error_category: error.category,
        upstream_status: error.upstreamStatus,
        error_recorded_at: now,
      });
    });
  }

  getHistoricalClaimState({ shopDomain, type, valueHash }) {
    const metadata = this.historicalIdentityMetadata.get(shopDomain);
    const run = metadata?.active_import_run_id
      ? this.historicalIdentityRuns.get(metadata.active_import_run_id)
      : null;
    if (run?.status !== "completed") return null;
    const customers = new Set([...this.historicalIdentityMembers.values()]
      .filter((member) => member.import_run_id === run.id && member.shop_domain === shopDomain
        && member.identity_type === type && member.value_hash === valueHash)
      .map((member) => member.shopify_customer_id));
    if (!customers.size) return null;
    return customers.size === 1 ? "active" : "conflicted";
  }

  async getFiscalCache(cnpj, now) {
    const cached = this.fiscalCache.get(cnpj);
    if (!cached || new Date(cached.expires_at) <= now) return null;
    return this.clone(cached);
  }

  async setFiscalCache({ cnpj, found, active, status, checkedAt, expiresAt }) {
    const cached = {
      cnpj_normalized: cnpj,
      found,
      active,
      status,
      checked_at: checkedAt,
      expires_at: expiresAt,
    };
    this.fiscalCache.set(cnpj, cached);
    return this.clone(cached);
  }

  addOutbox(registrationId, operation, now) {
    const existing = [...this.outbox.values()].find((i) => i.registration_id === registrationId && i.operation === operation && !i.processed_at);
    if (existing) return existing;
    const item = {
      id: this.idFactory(), registration_id: registrationId, operation, attempts: 0,
      next_attempt_at: now, processed_at: null, last_error: null, error_code: null,
      error_category: null, upstream_status: null, error_recorded_at: null,
      locked_at: null, created_at: now,
    };
    this.outbox.set(item.id, item);
    return item;
  }

  async associateWebhook({ eventId, topic, payloadDigest, payloadDigestVersion, email, emailClaim, customerId, now }) {
    return this.atomic(() => {
      if (this.webhooks.has(eventId)) return { duplicate: true };
      this.webhooks.set(eventId, {
        event_id: eventId, topic, payload_digest: payloadDigest,
        payload_digest_version: payloadDigestVersion, processed_at: now,
      });
      const registration = [...this.registrationIdentityClaims.values()]
        .filter((claim) => claim.identity_type === "email"
          && claim.key_version === emailClaim?.keyVersion
          && claim.value_hash === emailClaim?.valueHash
          && claim.claim_state !== "released")
        .map((claim) => this.registrations.get(claim.registration_id))
        .find((candidate) => candidate && new Date(candidate.expires_at) > now
          && ["reserved", "pending_shopify", "pending_validation"].includes(candidate.status))
        || [...this.registrations.values()].find((candidate) => candidate.email_normalized === email
          && new Date(candidate.expires_at) > now
          && ["reserved", "pending_shopify", "pending_validation"].includes(candidate.status));
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
      for (const claim of this.registrationIdentityClaims.values()) {
        if (claim.registration_id === registration.id && claim.claim_state === "reserved") {
          claim.claim_state = "active";
          claim.activated_at = now;
        }
      }
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
        const hasCnpj = registration.cnpj_normalized || [...this.registrationIdentityClaims.values()].some((claim) => (
          claim.registration_id === registration.id && claim.identity_type === "cnpj" && claim.claim_state !== "released"
        ));
        if (!hasCnpj) throw new AppError("missing_cnpj", 409);
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

  async completeOutbox({ item, registrationStatus, syncCompleted = false, now, payloadNeededUntil, enqueueApprove = false }) {
    return this.atomic(() => {
      const stored = this.outbox.get(item.id);
      Object.assign(stored, {
        processed_at: now, locked_at: null, last_error: null, error_code: null,
        error_category: null, upstream_status: null, error_recorded_at: null,
      });
      const registration = this.registrations.get(item.registration_id);
      registration.status = registrationStatus; registration.updated_at = now;
      if (syncCompleted) registration.sync_completed_at = now;
      if (syncCompleted) {
        for (const claim of this.registrationIdentityClaims.values()) {
          if (claim.registration_id !== registration.id || claim.claim_state === "released") continue;
          claim.claim_state = claim.identity_type === "cnpj" ? "tombstoned" : "active";
          claim.activated_at ||= now;
        }
        const payload = this.operationalPayloads.get(registration.id);
        if (payload && payloadNeededUntil) payload.needed_until = payloadNeededUntil;
      }
      if (enqueueApprove) this.addOutbox(registration.id, "approve_registration", now);
      return this.clone(registration);
    });
  }

  async failOutbox({ item, error, now, nextAttemptAt, terminal }) {
    return this.atomic(() => {
      const stored = this.outbox.get(item.id);
      stored.attempts += 1;
      Object.assign(stored, {
        last_error: null,
        error_code: error.code,
        error_category: error.category,
        upstream_status: error.upstreamStatus,
        error_recorded_at: now,
        next_attempt_at: nextAttemptAt,
        locked_at: null,
      });
      if (terminal) { stored.processed_at = now; this.registrations.get(item.registration_id).status = "failed"; }
    });
  }

  async enqueueReconciliation(registrationId) {
    return this.atomic(() => {
      const registration = this.registrations.get(registrationId);
      if (!registration) throw new AppError("registration_not_found", 404);
      const payload = this.operationalPayloads.get(registrationId);
      if ((!payload || payload.purged_at) && !(registration.cnpj_normalized && registration.phone_e164)) {
        throw new AppError("payload_purged", 409);
      }
      this.addOutbox(registrationId, "reconcile_registration", this.clock());
    });
  }

  async getOperationalPayload(registrationId) {
    return this.clone(this.operationalPayloads.get(registrationId) || null);
  }

  retentionCandidateSummary(config) {
    const cutoff = new Date(config.now.getTime() - config.operationalEventsMs);
    const held = (registration) => registration.retention_hold_until
      && new Date(registration.retention_hold_until) > config.now;
    const pendingOutbox = (registrationId) => [...this.outbox.values()].some((item) => (
      item.registration_id === registrationId && !item.processed_at
    ));
    const releaseIds = [...this.registrations.values()].filter((registration) => {
      if (registration.shopify_customer_id || held(registration) || pendingOutbox(registration.id)) return false;
      const expiryDue = new Date(registration.expires_at).getTime() + config.expiredUnlinkedMs <= config.now.getTime();
      const failedDue = ["failed", "rejected"].includes(registration.status)
        && new Date(registration.updated_at).getTime() + config.failedUnlinkedMs <= config.now.getTime();
      return ["failed", "rejected"].includes(registration.status) ? failedDue : expiryDue;
    }).map((registration) => registration.id);
    const payloadIds = [...this.operationalPayloads.values()].filter((payload) => {
      const registration = this.registrations.get(payload.registration_id);
      return !payload.purged_at && registration && !held(registration)
        && !pendingOutbox(registration.id)
        && ((registration.shopify_customer_id && registration.sync_completed_at
          && new Date(payload.needed_until) <= config.now)
          || releaseIds.includes(registration.id));
    }).map((payload) => payload.registration_id);
    const inactiveHistoricalRuns = [...this.historicalIdentityRuns.values()].filter((run) => {
      const active = [...this.historicalIdentityMetadata.values()].some((metadata) => metadata.active_import_run_id === run.id);
      return !active && ["failed", "completed"].includes(run.status)
        && run.completed_at && new Date(run.completed_at) <= cutoff;
    });
    return {
      releaseIds,
      payloadIds: [...new Set([...payloadIds, ...releaseIds])],
      releasedClaims: [...this.registrationIdentityClaims.values()].filter((claim) => (
        releaseIds.includes(claim.registration_id) && claim.claim_state !== "released"
      )).length,
      deletedOutbox: [...this.outbox.values()].filter((item) => item.processed_at && new Date(item.processed_at) <= cutoff).length,
      deletedWebhooks: [...this.webhooks.values()].filter((event) => new Date(event.processed_at) <= cutoff).length,
      deletedFiscal: [...this.fiscalCache.values()].filter((entry) => new Date(entry.expires_at) <= config.now).length,
      deletedBuckets: [...this.rateLimitBuckets.values()].filter((entry) => new Date(entry.expires_at) <= config.now).length,
      deletedAdmissions: [...this.registrationAdmissions.values()].filter((entry) => new Date(entry.expires_at) <= config.now).length,
      historicalRunIds: inactiveHistoricalRuns.map((run) => run.id),
      cutoff,
    };
  }

  async reportRetentionCandidates(config) {
    const candidates = this.retentionCandidateSummary(config);
    return {
      released_registrations: candidates.releaseIds.length,
      released_claims: candidates.releasedClaims,
      purged_payloads: candidates.payloadIds.length,
      deleted_outbox: candidates.deletedOutbox,
      deleted_webhook_events: candidates.deletedWebhooks,
      deleted_fiscal_cache: candidates.deletedFiscal,
      deleted_rate_limit_buckets: candidates.deletedBuckets,
      deleted_admissions: candidates.deletedAdmissions,
      deleted_historical_runs: candidates.historicalRunIds.length,
    };
  }

  async applyRetentionBatch(config) {
    return this.atomic(() => {
      const candidates = this.retentionCandidateSummary(config);
      const releaseIds = candidates.releaseIds.slice(0, config.batchSize);
      const payloadIds = candidates.payloadIds.slice(0, config.batchSize);
      let releasedClaims = 0;
      for (const registrationId of releaseIds) {
        const registration = this.registrations.get(registrationId);
        if (!registration || registration.shopify_customer_id) continue;
        for (const claim of this.registrationIdentityClaims.values()) {
          if (claim.registration_id === registrationId && claim.claim_state !== "released") {
            claim.claim_state = "released";
            claim.released_at = config.now;
            releasedClaims += 1;
          }
        }
        if (new Date(registration.expires_at) <= config.now) registration.status = "expired";
        registration.email_normalized = null;
        registration.cnpj_normalized = null;
        registration.phone_e164 = null;
      }
      let purgedPayloads = 0;
      for (const registrationId of payloadIds) {
        const payload = this.operationalPayloads.get(registrationId);
        const registration = this.registrations.get(registrationId);
        if (!payload || payload.purged_at || !registration) continue;
        payload.ciphertext = null; payload.nonce = null; payload.auth_tag = null; payload.purged_at = config.now;
        registration.email_normalized = null; registration.cnpj_normalized = null; registration.phone_e164 = null;
        purgedPayloads += 1;
      }
      const deleteLimited = (map, predicate) => {
        let count = 0;
        for (const [key, value] of map) {
          if (count >= config.batchSize) break;
          if (predicate(value)) { map.delete(key); count += 1; }
        }
        return count;
      };
      const deletedOutbox = deleteLimited(this.outbox, (item) => item.processed_at && new Date(item.processed_at) <= candidates.cutoff);
      const deletedWebhooks = deleteLimited(this.webhooks, (event) => new Date(event.processed_at) <= candidates.cutoff);
      const deletedFiscal = deleteLimited(this.fiscalCache, (entry) => new Date(entry.expires_at) <= config.now);
      const deletedBuckets = deleteLimited(this.rateLimitBuckets, (entry) => new Date(entry.expires_at) <= config.now);
      const deletedAdmissions = deleteLimited(this.registrationAdmissions, (entry) => new Date(entry.expires_at) <= config.now);
      let deletedHistoricalRuns = 0;
      for (const runId of candidates.historicalRunIds.slice(0, config.batchSize)) {
        for (const [key, state] of this.historicalIdentityStates) if (state.import_run_id === runId) this.historicalIdentityStates.delete(key);
        for (const [key, member] of this.historicalIdentityMembers) if (member.import_run_id === runId) this.historicalIdentityMembers.delete(key);
        this.historicalIdentityRuns.delete(runId);
        deletedHistoricalRuns += 1;
      }
      return {
        released_registrations: releaseIds.length,
        released_claims: releasedClaims,
        purged_payloads: purgedPayloads,
        deleted_outbox: deletedOutbox,
        deleted_webhook_events: deletedWebhooks,
        deleted_fiscal_cache: deletedFiscal,
        deleted_rate_limit_buckets: deletedBuckets,
        deleted_admissions: deletedAdmissions,
        deleted_historical_runs: deletedHistoricalRuns,
      };
    });
  }

  async getRegistration(id) { return this.clone(this.registrations.get(id) || null); }
  simulationCustomer(customerId) {
    if (!this.simulationCustomers.has(customerId)) this.simulationCustomers.set(customerId, { id: customerId, phone: null, tags: [], metafields: { nodes: [] } });
    return this.simulationCustomers.get(customerId);
  }
  async setSimulationPhone(customerId, phone) { this.simulationCustomer(customerId).phone = phone; }
  async setSimulationMetafields(customerId, fields) {
    const customer = this.simulationCustomer(customerId);
    const current = new Map(customer.metafields.nodes.map((field) => [field.key, field]));
    for (const field of fields) current.set(field.key, { key: field.key, value: String(field.value), type: field.type });
    customer.metafields.nodes = [...current.values()];
  }
  async addSimulationTags(customerId, tags) {
    const customer = this.simulationCustomer(customerId);
    customer.tags = [...new Set([...customer.tags, ...tags])];
  }
  async removeSimulationTags(customerId, tags) {
    const customer = this.simulationCustomer(customerId);
    customer.tags = customer.tags.filter((tag) => !tags.includes(tag));
  }
  async getSimulationCustomer(customerId) { return this.clone(this.simulationCustomers.get(customerId) || null); }
  async close() {}
}
