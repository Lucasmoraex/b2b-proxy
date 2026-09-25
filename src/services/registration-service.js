import crypto from "node:crypto";
import { AppError, ExternalServiceError } from "../errors.js";
import { signRegistrationToken } from "../security.js";
import {
  normalizeBrazilianPhone,
  normalizeCnpj,
  normalizeEmail,
  normalizeEmployeeRange,
  validateUuid,
} from "../validation.js";
import { identityIndexSecretFingerprint, registrationIdentityClaims } from "../identity/historical-identities.js";
import { registrationAdmissionDigest, registrationRateLimitIdentityKeys } from "../rate-limit.js";
import { DATA_DIGEST_VERSION, registrationRequestDigest } from "../data-digests.js";
import { buildRegistrationIdentityClaims } from "../registration-identities.js";
import { encryptRegistrationOperationalPayload } from "../pii-crypto.js";

export class RegistrationService {
  constructor({
    store,
    registryClient,
    clock,
    reservationTtlMs,
    fiscalCacheTtlMs = 24 * 60 * 60 * 1000,
    fiscalCacheEnabled = true,
    registrationTokenSecret,
    dataDigestSecret,
    piiKeyring,
    idFactory = () => crypto.randomUUID(),
    historicalIdentityLookupEnabled = false,
    historicalIdentityShopDomain = "",
    historicalIdentityIndexSecret = "",
    rateLimitKeySecret,
    sharedRateLimitWindowMs,
    sharedRateLimitMax,
    identityRateLimitWindowMs,
    identityRateLimitMax,
    activeReservationsPerIpMax,
    rateLimitStateRetentionMs,
    rateLimitCleanupBatchSize,
  }) {
    this.store = store;
    this.registryClient = registryClient;
    this.clock = clock;
    this.reservationTtlMs = reservationTtlMs;
    this.fiscalCacheTtlMs = fiscalCacheTtlMs;
    this.fiscalCacheEnabled = fiscalCacheEnabled;
    this.registrationTokenSecret = registrationTokenSecret;
    this.dataDigestSecret = dataDigestSecret;
    this.piiKeyring = piiKeyring;
    this.idFactory = idFactory;
    this.historicalIdentityLookupEnabled = historicalIdentityLookupEnabled;
    this.historicalIdentityShopDomain = historicalIdentityShopDomain;
    this.historicalIdentityIndexSecret = historicalIdentityIndexSecret;
    this.historicalIdentitySecretFingerprint = historicalIdentityLookupEnabled
      ? identityIndexSecretFingerprint(historicalIdentityIndexSecret)
      : null;
    this.rateLimitKeySecret = rateLimitKeySecret;
    this.sharedRateLimitWindowMs = sharedRateLimitWindowMs;
    this.sharedRateLimitMax = sharedRateLimitMax;
    this.identityRateLimitWindowMs = identityRateLimitWindowMs;
    this.identityRateLimitMax = identityRateLimitMax;
    this.activeReservationsPerIpMax = activeReservationsPerIpMax;
    this.rateLimitStateRetentionMs = rateLimitStateRetentionMs;
    this.rateLimitCleanupBatchSize = rateLimitCleanupBatchSize;
  }

  response(registration) {
    return {
      ok: true,
      registration_id: registration.id,
      registration_token: signRegistrationToken(registration, this.registrationTokenSecret),
      status: registration.status,
      expires_at: new Date(registration.expires_at).toISOString(),
    };
  }

  async create(body, idempotencyHeader, { ipHash } = {}) {
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new AppError("invalid_request", 422);
    const allowed = new Set(["email", "cnpj", "phone", "employee_range"]);
    if (Object.keys(body).some((key) => !allowed.has(key))) throw new AppError("invalid_request", 422);
    const idempotencyKey = validateUuid(idempotencyHeader);
    const email = normalizeEmail(body?.email);
    const cnpj = normalizeCnpj(body?.cnpj);
    const phone = normalizeBrazilianPhone(body?.phone);
    const employeeRange = normalizeEmployeeRange(body?.employee_range);
    const requestDigest = registrationRequestDigest({
      email, cnpj, phone, employee_range: employeeRange,
    }, this.dataDigestSecret);
    const now = this.clock();

    const previous = await this.store.findByIdempotencyKey(idempotencyKey);
    if (previous && (previous.shopify_customer_id || new Date(previous.expires_at) > now)) {
      if (previous.request_digest_version !== DATA_DIGEST_VERSION || previous.request_digest !== requestDigest) {
        throw new AppError("idempotency_conflict", 409);
      }
      return this.response(previous);
    }

    if (typeof ipHash !== "string" || !/^[0-9a-f]{64}$/.test(ipHash)) {
      throw new AppError("internal_error", 500);
    }
    await this.store.consumeRegistrationQuota({
      idempotencyKey,
      requestKeyDigest: registrationAdmissionDigest(requestDigest, this.dataDigestSecret),
      requestKeyDigestVersion: DATA_DIGEST_VERSION,
      ipHash,
      identityKeys: registrationRateLimitIdentityKeys({
        email, cnpj, phone, secret: this.rateLimitKeySecret,
      }),
      now,
      sharedWindowMs: this.sharedRateLimitWindowMs,
      sharedMax: this.sharedRateLimitMax,
      identityWindowMs: this.identityRateLimitWindowMs,
      identityMax: this.identityRateLimitMax,
      activeReservationsMax: this.activeReservationsPerIpMax,
      stateRetentionMs: this.rateLimitStateRetentionMs,
      cleanupBatchSize: this.rateLimitCleanupBatchSize,
    });

    const registrationClaims = buildRegistrationIdentityClaims({
      email, cnpj, phone, secret: this.dataDigestSecret,
    });
    const conflict = await this.store.findConflict({ email, cnpj, phone, identityClaims: registrationClaims, now });
    if (conflict) throw new AppError(conflict, 409);

    const historicalIdentity = this.historicalIdentityLookupEnabled ? {
      shopDomain: this.historicalIdentityShopDomain,
      secretFingerprint: this.historicalIdentitySecretFingerprint,
      claims: registrationIdentityClaims({
        email, cnpj, phone, secret: this.historicalIdentityIndexSecret,
      }),
    } : null;
    if (historicalIdentity) {
      const historicalConflict = await this.store.findHistoricalConflict(historicalIdentity);
      if (historicalConflict) throw new AppError(historicalConflict, 409);
    }

    let fiscal = this.fiscalCacheEnabled
      ? await this.store.getFiscalCache(cnpj, now)
      : null;

    if (!fiscal) {
      try {
        fiscal = await this.registryClient.checkCnpj(cnpj);
      } catch (error) {
        if (error instanceof ExternalServiceError) throw error;
        throw new ExternalServiceError("registry", "registry_unavailable", { cause: error });
      }

      if (this.fiscalCacheEnabled) {
        const checkedAt = this.clock();
        await this.store.setFiscalCache({
          cnpj,
          found: Boolean(fiscal.found),
          active: Boolean(fiscal.active),
          status: String(fiscal.status || ""),
          checkedAt,
          expiresAt: new Date(checkedAt.getTime() + this.fiscalCacheTtlMs),
        });
      }
    }
    if (!fiscal.found || !fiscal.active || fiscal.status !== "ATIVA") throw new AppError("inactive_cnpj", 422);

    const expiresAt = new Date(now.getTime() + this.reservationTtlMs);
    const registrationId = this.idFactory();
    const operationalPayload = encryptRegistrationOperationalPayload({
      registrationId,
      payload: { email, cnpj, phone, employee_range: employeeRange },
      keyring: this.piiKeyring,
    });
    const result = await this.store.reserve({
      registrationId,
      email, cnpj, phone, idempotencyKey, requestDigest, requestDigestVersion: DATA_DIGEST_VERSION,
      employeeRangeRequired: true,
      registrationClaims,
      operationalPayload: { ...operationalPayload, neededUntil: expiresAt },
      fiscalStatus: "ATIVA", now, expiresAt,
      historicalIdentity,
      requestIpHash: ipHash,
      activeReservationsMax: this.activeReservationsPerIpMax,
    });
    return this.response(result.registration);
  }
}
