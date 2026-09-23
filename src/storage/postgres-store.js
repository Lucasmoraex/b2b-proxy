import crypto from "node:crypto";
import { AppError } from "../errors.js";
import { registrationIdentityClaims } from "../identity/historical-identities.js";
import {
  acquireHistoricalAdvisoryLocks,
  acquireHistoricalPromotionExclusiveLock,
  acquireHistoricalPromotionSharedLock,
} from "./historical-locks.js";

const CONSTRAINT_ERRORS = {
  registrations_email_unique: "email_in_use",
  registrations_cnpj_unique: "cnpj_in_use",
  registrations_phone_unique: "phone_in_use",
  registrations_idempotency_unique: "idempotency_conflict",
  registrations_shopify_customer_unique: "shopify_customer_in_use",
  registration_identity_claims_blocking_unique: "identity_in_use",
};

const mapRow = (row) => row ? { ...row } : null;

const HISTORICAL_CONFLICT_CODES = Object.freeze({
  email: "email_in_use",
  cnpj: "cnpj_in_use",
  phone: "phone_in_use",
});

const activeRegistrationPredicate = `NOT (
  expires_at <= $2 AND shopify_customer_id IS NULL
  AND status IN ('reserved','pending_shopify','expired')
)`;

const assertHistoricalMetadata = async (client, shopDomain, secretFingerprint, { lock = false } = {}) => {
  const result = await client.query(`SELECT secret_fingerprint, active_import_run_id
    FROM historical_identity_index_metadata WHERE shop_domain=$1${lock ? " FOR UPDATE" : ""}`, [shopDomain]);
  if (!result.rowCount || result.rows[0].secret_fingerprint !== secretFingerprint) {
    throw new AppError("identity_index_unavailable", 503);
  }
  return result.rows[0];
};

const assertActiveHistoricalSnapshot = async (client, shopDomain, secretFingerprint) => {
  const result = await client.query(`SELECT metadata.active_import_run_id
    FROM historical_identity_index_metadata metadata
    JOIN historical_identity_import_runs import_run
      ON import_run.id=metadata.active_import_run_id
      AND import_run.shop_domain=metadata.shop_domain
      AND import_run.status='completed'
    WHERE metadata.shop_domain=$1 AND metadata.secret_fingerprint=$2`, [shopDomain, secretFingerprint]);
  if (!result.rowCount) throw new AppError("identity_index_unavailable", 503);
  return result.rows[0].active_import_run_id;
};

const queryHistoricalConflict = async (client, { shopDomain, claims, activeRunId }) => {
  if (!claims?.length) return null;
  const values = claims.map((claim, index) => `($${index * 2 + 2}::text,$${index * 2 + 3}::char(64))`).join(",");
  const params = [shopDomain, ...claims.flatMap((claim) => [claim.type, claim.valueHash])];
  const result = await client.query(`SELECT candidate.identity_type
    FROM (VALUES ${values}) AS candidate(identity_type, value_hash)
    JOIN historical_identity_snapshot_members member
      ON member.shop_domain=$1
      AND member.import_run_id=$${params.length + 1}
      AND member.identity_type=candidate.identity_type
      AND member.value_hash=candidate.value_hash
      AND member.validity='valid'
    ORDER BY CASE candidate.identity_type WHEN 'email' THEN 1 WHEN 'cnpj' THEN 2 ELSE 3 END
    LIMIT 1`, [...params, activeRunId]);
  return result.rows[0] ? HISTORICAL_CONFLICT_CODES[result.rows[0].identity_type] : null;
};

const queryRegistrationClaimConflict = async (client, identityClaims, now) => {
  if (!identityClaims?.length) return null;
  const values = identityClaims.map((claim, index) => (
    `($${index * 3 + 1}::text,$${index * 3 + 2}::text,$${index * 3 + 3}::char(64))`
  )).join(",");
  const params = identityClaims.flatMap((claim) => [claim.type, claim.keyVersion, claim.valueHash]);
  const nowIndex = params.length + 1;
  const result = await client.query(`SELECT candidate.identity_type
    FROM (VALUES ${values}) AS candidate(identity_type, key_version, value_hash)
    JOIN registration_identity_claims claim
      ON claim.identity_type=candidate.identity_type
      AND claim.key_version=candidate.key_version
      AND claim.value_hash=candidate.value_hash
      AND claim.claim_state <> 'released'
    JOIN registrations registration ON registration.id=claim.registration_id
    WHERE NOT (
      claim.claim_state='reserved'
      AND registration.shopify_customer_id IS NULL
      AND registration.expires_at <= $${nowIndex}
    )
    ORDER BY CASE candidate.identity_type WHEN 'email' THEN 1 WHEN 'cnpj' THEN 2 ELSE 3 END
    LIMIT 1`, [...params, now]);
  return result.rows[0] ? HISTORICAL_CONFLICT_CODES[result.rows[0].identity_type] : null;
};

export class PostgresRegistrationStore {
  constructor({ pool, clock = () => new Date(), idFactory = () => crypto.randomUUID() }) {
    this.pool = pool;
    this.clock = clock;
    this.idFactory = idFactory;
  }

  async transaction(fn, isolation = "READ COMMITTED") {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SET TRANSACTION ISOLATION LEVEL ${isolation}`);
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") throw new AppError(CONSTRAINT_ERRORS[error.constraint] || "conflict", 409);
      throw error;
    } finally {
      client.release();
    }
  }

  async reserve(input) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.transaction(async (client) => {
          const existingResult = await client.query("SELECT * FROM registrations WHERE idempotency_key = $1 FOR UPDATE", [input.idempotencyKey]);
          const existing = existingResult.rows[0];
          if (existing && (existing.shopify_customer_id || new Date(existing.expires_at) > input.now)) {
            if (existing.request_digest_version !== input.requestDigestVersion
              || existing.request_digest !== input.requestDigest) throw new AppError("idempotency_conflict", 409);
            return { registration: mapRow(existing), reused: true };
          }
          if (existing && existing.shopify_customer_id) throw new AppError("idempotency_conflict", 409);

          await client.query(`UPDATE registration_identity_claims claim SET
              claim_state='released', released_at=$1
            FROM registrations registration
            WHERE registration.id=claim.registration_id
              AND claim.claim_state='reserved'
              AND registration.shopify_customer_id IS NULL
              AND registration.expires_at <= $1`, [input.now]);
          await client.query(`UPDATE registrations SET status='expired', updated_at=$1,
              email_normalized=NULL, cnpj_normalized=NULL, phone_e164=NULL
            WHERE shopify_customer_id IS NULL AND expires_at <= $1
              AND status IN ('reserved','pending_shopify')`, [input.now]);

          if (input.historicalIdentity) {
            const historical = input.historicalIdentity;
            await acquireHistoricalPromotionSharedLock(client, historical.shopDomain);
            const activeRunId = await assertActiveHistoricalSnapshot(client, historical.shopDomain, historical.secretFingerprint);
            await acquireHistoricalAdvisoryLocks(client, historical.shopDomain, historical.claims);
            const conflict = await queryHistoricalConflict(client, { ...historical, activeRunId });
            if (conflict) throw new AppError(conflict, 409);
          }

          if (input.requestIpHash && input.activeReservationsMax) {
            await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`registration-ip:${input.requestIpHash}`]);
          }

          const claimConflict = await queryRegistrationClaimConflict(client, input.registrationClaims || [], input.now);
          if (claimConflict) throw new AppError(claimConflict, 409);

          if (input.requestIpHash && input.activeReservationsMax) {
            const active = await client.query(`SELECT count(*)::integer AS count
              FROM registrations
              WHERE request_ip_hash=$1 AND shopify_customer_id IS NULL
                AND expires_at > $2
                AND status IN ('reserved','pending_shopify','pending_validation','pending_review')`,
            [input.requestIpHash, input.now]);
            if (active.rows[0].count >= input.activeReservationsMax) throw new AppError("rate_limited", 429);
          }

          const id = input.registrationId || this.idFactory();
          const minimized = Boolean(input.operationalPayload && input.registrationClaims?.length === 3);
          const result = await client.query(`INSERT INTO registrations (
              id, email_normalized, cnpj_normalized, phone_e164, status,
              idempotency_key, request_digest, request_digest_version, fiscal_status, fiscal_validated_at,
              expires_at, request_ip_hash, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,'reserved',$5,$6,$7,$8,$9,$10,$11,$9,$9)
            RETURNING *`, [
            id, minimized ? null : input.email, minimized ? null : input.cnpj,
            minimized ? null : input.phone, input.idempotencyKey,
            input.requestDigest, input.requestDigestVersion, input.fiscalStatus, input.now, input.expiresAt,
            input.requestIpHash || null,
          ]);
          for (const claim of input.registrationClaims || []) {
            await client.query(`INSERT INTO registration_identity_claims (
                registration_id, identity_type, key_version, value_hash, claim_state, created_at
              ) VALUES ($1,$2,$3,$4,'reserved',$5)`, [
              id, claim.type, claim.keyVersion, claim.valueHash, input.now,
            ]);
          }
          if (input.operationalPayload) {
            await client.query(`INSERT INTO registration_operational_payloads (
                registration_id, ciphertext, nonce, auth_tag, encryption_key_version,
                needed_until, created_at
              ) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [
              id,
              input.operationalPayload.ciphertext,
              input.operationalPayload.nonce,
              input.operationalPayload.authTag,
              input.operationalPayload.encryptionKeyVersion,
              input.operationalPayload.neededUntil,
              input.now,
            ]);
          }
          return { registration: mapRow(result.rows[0]), reused: false };
        }, "SERIALIZABLE");
      } catch (error) {
        if (error.code === "40001" && attempt < 2) continue;
        if (error.code === "identity_in_use") {
          const conflict = await queryRegistrationClaimConflict(this.pool, input.registrationClaims || [], input.now);
          throw new AppError(conflict || "conflict", 409);
        }
        throw error;
      }
    }
    throw new AppError("internal_error", 500);
  }

  async findByIdempotencyKey(idempotencyKey) {
    const result = await this.pool.query("SELECT * FROM registrations WHERE idempotency_key=$1", [idempotencyKey]);
    return mapRow(result.rows[0]);
  }

  async consumeRegistrationQuota(input) {
    return this.transaction(async (client) => {
      await client.query(`DELETE FROM registration_request_admissions
        WHERE idempotency_key=$1 AND expires_at <= $2`, [input.idempotencyKey, input.now]);
      await client.query(`WITH expired AS (
          SELECT ctid FROM registration_rate_limit_buckets
          WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2
        ) DELETE FROM registration_rate_limit_buckets bucket
          USING expired WHERE bucket.ctid=expired.ctid`, [input.now, input.cleanupBatchSize]);
      await client.query(`WITH expired AS (
          SELECT ctid FROM registration_request_admissions
          WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2
        ) DELETE FROM registration_request_admissions admission
          USING expired WHERE admission.ctid=expired.ctid`, [input.now, input.cleanupBatchSize]);

      const admission = await client.query(`INSERT INTO registration_request_admissions (
          idempotency_key, request_key_digest, request_key_digest_version, ip_key_hash, admitted_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (idempotency_key) DO NOTHING
        RETURNING idempotency_key`, [
        input.idempotencyKey,
        input.requestKeyDigest,
        input.requestKeyDigestVersion,
        input.ipHash,
        input.now,
        new Date(input.now.getTime() + input.stateRetentionMs),
      ]);
      if (!admission.rowCount) {
        const previous = await client.query(`SELECT request_key_digest, request_key_digest_version
          FROM registration_request_admissions WHERE idempotency_key=$1`, [input.idempotencyKey]);
        if (previous.rows[0]?.request_key_digest_version !== input.requestKeyDigestVersion
          || previous.rows[0]?.request_key_digest !== input.requestKeyDigest) {
          throw new AppError("idempotency_conflict", 409);
        }
        return { reused: true };
      }

      const active = await client.query(`SELECT count(*)::integer AS count
        FROM registrations
        WHERE request_ip_hash=$1 AND shopify_customer_id IS NULL
          AND expires_at > $2
          AND status IN ('reserved','pending_shopify','pending_validation','pending_review')`,
      [input.ipHash, input.now]);
      if (active.rows[0].count >= input.activeReservationsMax) throw new AppError("rate_limited", 429);

      const buckets = [
        { scope: "registration_ip", keyHash: input.ipHash, windowMs: input.sharedWindowMs, max: input.sharedMax },
        ...input.identityKeys.map((identity) => ({
          scope: `registration_identity_${identity.type}`,
          keyHash: identity.keyHash,
          windowMs: input.identityWindowMs,
          max: input.identityMax,
        })),
      ];
      for (const bucket of buckets) {
        const windowStartedAt = new Date(Math.floor(input.now.getTime() / bucket.windowMs) * bucket.windowMs);
        const expiresAt = new Date(windowStartedAt.getTime() + bucket.windowMs + input.stateRetentionMs);
        const consumed = await client.query(`INSERT INTO registration_rate_limit_buckets (
            scope, key_hash, window_started_at, hit_count, expires_at, updated_at
          ) VALUES ($1,$2,$3,1,$4,$5)
          ON CONFLICT (scope, key_hash, window_started_at) DO UPDATE SET
            hit_count=registration_rate_limit_buckets.hit_count + 1,
            expires_at=GREATEST(registration_rate_limit_buckets.expires_at, EXCLUDED.expires_at),
            updated_at=EXCLUDED.updated_at
          WHERE registration_rate_limit_buckets.hit_count < $6
          RETURNING hit_count`, [
          bucket.scope, bucket.keyHash, windowStartedAt, expiresAt, input.now, bucket.max,
        ]);
        if (!consumed.rowCount) throw new AppError("rate_limited", 429);
      }
      return { reused: false };
    });
  }

  async cleanupRegistrationAbuseState({ now, batchSize = 200 }) {
    return this.transaction(async (client) => {
      const buckets = await client.query(`WITH expired AS (
          SELECT ctid FROM registration_rate_limit_buckets
          WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2
        ) DELETE FROM registration_rate_limit_buckets bucket
          USING expired WHERE bucket.ctid=expired.ctid RETURNING 1`, [now, batchSize]);
      const admissions = await client.query(`WITH expired AS (
          SELECT ctid FROM registration_request_admissions
          WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2
        ) DELETE FROM registration_request_admissions admission
          USING expired WHERE admission.ctid=expired.ctid RETURNING 1`, [now, batchSize]);
      return { buckets: buckets.rowCount, admissions: admissions.rowCount };
    });
  }

  async findConflict({ email, cnpj, phone, identityClaims = [], now }) {
    const claimConflict = await queryRegistrationClaimConflict(this.pool, identityClaims, now);
    if (claimConflict) return claimConflict;
    const result = await this.pool.query(`SELECT code FROM (
      SELECT 'email_in_use' AS code, 1 AS priority
        FROM registrations
        WHERE email_normalized=$1
          AND NOT (expires_at <= $4 AND shopify_customer_id IS NULL
            AND status IN ('reserved','pending_shopify','expired'))
      UNION ALL
      SELECT 'cnpj_in_use' AS code, 2 AS priority
        FROM registrations
        WHERE cnpj_normalized=$2
          AND NOT (expires_at <= $4 AND shopify_customer_id IS NULL
            AND status IN ('reserved','pending_shopify','expired'))
      UNION ALL
      SELECT 'phone_in_use' AS code, 3 AS priority
        FROM registrations
        WHERE phone_e164=$3
          AND NOT (expires_at <= $4 AND shopify_customer_id IS NULL
            AND status IN ('reserved','pending_shopify','expired'))
    ) conflicts ORDER BY priority LIMIT 1`, [email, cnpj, phone, now]);
    return result.rows[0]?.code || null;
  }

  async findHistoricalConflict({ shopDomain, claims, secretFingerprint }) {
    const activeRunId = await assertActiveHistoricalSnapshot(this.pool, shopDomain, secretFingerprint);
    return queryHistoricalConflict(this.pool, { shopDomain, claims, activeRunId });
  }

  async beginHistoricalIdentityImport({ runId, shopDomain, secretFingerprint, now }) {
    return this.transaction(async (client) => {
      await client.query(`INSERT INTO historical_identity_index_metadata (
          shop_domain, secret_fingerprint, created_at, verified_at
        ) VALUES ($1,$2,$3,$3) ON CONFLICT (shop_domain) DO NOTHING`,
      [shopDomain, secretFingerprint, now]);
      await assertHistoricalMetadata(client, shopDomain, secretFingerprint, { lock: true });
      await client.query("UPDATE historical_identity_index_metadata SET verified_at=$2 WHERE shop_domain=$1", [shopDomain, now]);
      await client.query(`INSERT INTO historical_identity_import_runs (
          id, shop_domain, secret_fingerprint, status, started_at
        ) VALUES ($1,$2,$3,'staging',$4)`, [runId, shopDomain, secretFingerprint, now]);
    });
  }

  async importHistoricalIdentityPage({ runId, shopDomain, secretFingerprint, customers, now }) {
    return this.transaction(async (client) => {
      await assertHistoricalMetadata(client, shopDomain, secretFingerprint);
      const run = await client.query(`SELECT status FROM historical_identity_import_runs
        WHERE id=$1 AND shop_domain=$2 FOR UPDATE`, [runId, shopDomain]);
      if (run.rows[0]?.status !== "staging") throw new Error("historical_identity_import_not_staging");
      const claims = customers.flatMap((customer) => customer.claims);
      await acquireHistoricalAdvisoryLocks(client, shopDomain, claims);

      for (const customer of customers) {
        for (const claim of customer.claims) {
          const fields = { email: "email_normalized", cnpj: "cnpj_normalized", phone: "phone_e164" };
          const field = fields[claim.type];
          if (!field) throw new Error("historical_identity_type_invalid");
          if (claim.registrationValueHash && claim.registrationKeyVersion) {
            const indexedRegistration = await client.query(`SELECT registration.shopify_customer_id
              FROM registration_identity_claims identity_claim
              JOIN registrations registration ON registration.id=identity_claim.registration_id
              WHERE identity_claim.identity_type=$1
                AND identity_claim.key_version=$2
                AND identity_claim.value_hash=$3
                AND identity_claim.claim_state <> 'released'
                AND NOT (identity_claim.claim_state='reserved'
                  AND registration.shopify_customer_id IS NULL AND registration.expires_at <= $4)
                AND registration.shopify_customer_id IS DISTINCT FROM $5
              LIMIT 1`, [
              claim.type, claim.registrationKeyVersion, claim.registrationValueHash, now, customer.customerId,
            ]);
            if (indexedRegistration.rowCount) throw new Error("historical_identity_registration_conflict");
          }
          const registration = await client.query(`SELECT shopify_customer_id FROM registrations
            WHERE ${field}=$1 AND ${activeRegistrationPredicate}
              AND shopify_customer_id IS DISTINCT FROM $3
            LIMIT 1`, [claim.normalized, now, customer.customerId]);
          if (registration.rowCount) throw new Error("historical_identity_registration_conflict");
        }
      }

      for (const customer of customers) {
        for (const state of customer.states) {
          await client.query(`INSERT INTO historical_customer_identity_snapshot_states (
              import_run_id, shop_domain, shopify_customer_id, identity_type, validity, sources, imported_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (import_run_id, shop_domain, shopify_customer_id, identity_type) DO UPDATE SET
              validity=EXCLUDED.validity,
              sources=EXCLUDED.sources,
              imported_at=EXCLUDED.imported_at`,
          [runId, shopDomain, customer.customerId, state.type, state.validity, state.sources, now]);
        }
        for (const claim of customer.claims) {
          await client.query(`INSERT INTO historical_identity_snapshot_members (
              import_run_id, shop_domain, shopify_customer_id, identity_type, value_hash,
              registration_key_version, registration_value_hash, validity, sources, imported_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,'valid',$8,$9)
            ON CONFLICT (import_run_id, shop_domain, shopify_customer_id, identity_type, value_hash) DO UPDATE SET
              registration_key_version=EXCLUDED.registration_key_version,
              registration_value_hash=EXCLUDED.registration_value_hash,
              sources=ARRAY(SELECT DISTINCT source FROM unnest(
                historical_identity_snapshot_members.sources || EXCLUDED.sources
              ) AS source ORDER BY source),
              imported_at=EXCLUDED.imported_at`,
          [
            runId, shopDomain, customer.customerId, claim.type, claim.valueHash,
            claim.registrationKeyVersion, claim.registrationValueHash, claim.sources, now,
          ]);
        }
      }
    }, "SERIALIZABLE");
  }

  async completeHistoricalIdentityImport({ runId, shopDomain, secretFingerprint, identityIndexSecret, summary, now }) {
    return this.transaction(async (client) => {
      await acquireHistoricalPromotionExclusiveLock(client, shopDomain);
      const metadata = await assertHistoricalMetadata(client, shopDomain, secretFingerprint, { lock: true });
      const run = await client.query(`SELECT status FROM historical_identity_import_runs
        WHERE id=$1 AND shop_domain=$2 FOR UPDATE`, [runId, shopDomain]);
      if (run.rows[0]?.status !== "staging") throw new Error("historical_identity_import_not_staging");

      if (metadata.active_import_run_id) {
        await client.query(`INSERT INTO historical_customer_identity_snapshot_states (
            import_run_id, shop_domain, shopify_customer_id, identity_type, validity, sources, imported_at
          ) SELECT $1, shop_domain, shopify_customer_id, identity_type, validity, sources, $3
            FROM historical_customer_identity_snapshot_states
            WHERE import_run_id=$2 AND shop_domain=$4
          ON CONFLICT (import_run_id, shop_domain, shopify_customer_id, identity_type) DO NOTHING`,
        [runId, metadata.active_import_run_id, now, shopDomain]);
        await client.query(`INSERT INTO historical_identity_snapshot_members (
            import_run_id, shop_domain, shopify_customer_id, identity_type, value_hash,
            registration_key_version, registration_value_hash, validity, sources, imported_at
          ) SELECT $1, shop_domain, shopify_customer_id, identity_type, value_hash,
              registration_key_version, registration_value_hash, validity, sources, $3
            FROM historical_identity_snapshot_members
            WHERE import_run_id=$2 AND shop_domain=$4
          ON CONFLICT (import_run_id, shop_domain, shopify_customer_id, identity_type, value_hash) DO NOTHING`,
        [runId, metadata.active_import_run_id, now, shopDomain]);
      }

      const registrations = await client.query(`SELECT email_normalized, cnpj_normalized, phone_e164, shopify_customer_id
        FROM registrations WHERE NOT (
          expires_at <= $1 AND shopify_customer_id IS NULL
          AND status IN ('reserved','pending_shopify','expired')
        ) AND email_normalized IS NOT NULL AND cnpj_normalized IS NOT NULL
          AND phone_e164 IS NOT NULL`, [now]);
      for (const registration of registrations.rows) {
        const claims = registrationIdentityClaims({
          email: registration.email_normalized,
          cnpj: registration.cnpj_normalized,
          phone: registration.phone_e164,
          secret: identityIndexSecret,
        });
        for (const claim of claims) {
          const conflict = await client.query(`SELECT 1 FROM historical_identity_snapshot_members
            WHERE import_run_id=$1 AND shop_domain=$2 AND identity_type=$3 AND value_hash=$4
              AND shopify_customer_id IS DISTINCT FROM $5 LIMIT 1`,
          [runId, shopDomain, claim.type, claim.valueHash, registration.shopify_customer_id]);
          if (conflict.rowCount) throw new Error("historical_identity_registration_conflict");
        }
      }

      const indexedClaims = await client.query(`SELECT claim.identity_type, claim.key_version,
          claim.value_hash, registration.shopify_customer_id
        FROM registration_identity_claims claim
        JOIN registrations registration ON registration.id=claim.registration_id
        WHERE claim.claim_state <> 'released'
          AND NOT (claim.claim_state='reserved' AND registration.shopify_customer_id IS NULL
            AND registration.expires_at <= $1)`, [now]);
      for (const claim of indexedClaims.rows) {
        const conflict = await client.query(`SELECT 1 FROM historical_identity_snapshot_members
          WHERE import_run_id=$1 AND shop_domain=$2 AND identity_type=$3
            AND registration_key_version=$4 AND registration_value_hash=$5
            AND shopify_customer_id IS DISTINCT FROM $6 LIMIT 1`, [
          runId, shopDomain, claim.identity_type, claim.key_version,
          claim.value_hash, claim.shopify_customer_id,
        ]);
        if (conflict.rowCount) throw new Error("historical_identity_registration_conflict");
      }

      await client.query(`UPDATE historical_identity_import_runs SET
        status='completed', completed_at=$2, pages_scanned=$3, customers_scanned=$4,
        claims_processed=$5, states_processed=$6, last_error=NULL,
        error_code=NULL, error_category=NULL, upstream_status=NULL, error_recorded_at=NULL WHERE id=$1`, [
        runId, now, summary.pages_scanned, summary.customers_scanned,
        summary.claims_processed, summary.states_processed,
      ]);
      await client.query(`UPDATE historical_identity_index_metadata
        SET active_import_run_id=$2, verified_at=$3 WHERE shop_domain=$1`, [shopDomain, runId, now]);
    }, "SERIALIZABLE");
  }

  async failHistoricalIdentityImport({ runId, error, now }) {
    await this.pool.query(`UPDATE historical_identity_import_runs SET
      status='failed', completed_at=$2, last_error=NULL,
      error_code=$3, error_category=$4, upstream_status=$5, error_recorded_at=$2
      WHERE id=$1 AND status='staging'`,
    [runId, now, error.code, error.category, error.upstreamStatus]);
  }

  async getFiscalCache(cnpj, now) {
    const result = await this.pool.query(`SELECT * FROM fiscal_registry_cache
      WHERE cnpj_normalized=$1 AND expires_at>$2`, [cnpj, now]);
    return mapRow(result.rows[0]);
  }

  async setFiscalCache({ cnpj, found, active, status, checkedAt, expiresAt }) {
    const result = await this.pool.query(`INSERT INTO fiscal_registry_cache (
        cnpj_normalized, found, active, status, checked_at, expires_at
      ) VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (cnpj_normalized) DO UPDATE SET
        found=EXCLUDED.found,
        active=EXCLUDED.active,
        status=EXCLUDED.status,
        checked_at=EXCLUDED.checked_at,
        expires_at=EXCLUDED.expires_at
      RETURNING *`, [cnpj, found, active, status, checkedAt, expiresAt]);
    return mapRow(result.rows[0]);
  }

  async associateWebhook({ eventId, topic, payloadDigest, payloadDigestVersion, email, emailClaim, customerId, now }) {
    return this.transaction(async (client) => {
      const inserted = await client.query(`INSERT INTO webhook_events (
          event_id, topic, payload_digest, payload_digest_version, processed_at
        ) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (event_id) DO NOTHING RETURNING event_id`,
      [eventId, topic, payloadDigest, payloadDigestVersion, now]);
      if (!inserted.rowCount) return { duplicate: true };

      let found = emailClaim ? await client.query(`SELECT registration.* FROM registrations registration
        JOIN registration_identity_claims claim ON claim.registration_id=registration.id
        WHERE claim.identity_type='email' AND claim.key_version=$1 AND claim.value_hash=$2
          AND claim.claim_state <> 'released' AND registration.expires_at > $3
          AND registration.status IN ('reserved','pending_shopify','pending_validation')
        FOR UPDATE OF registration`, [emailClaim.keyVersion, emailClaim.valueHash, now]) : { rows: [] };
      if (!found.rows[0]) {
        found = await client.query(`SELECT * FROM registrations
          WHERE email_normalized = $1 AND expires_at > $2
            AND status IN ('reserved','pending_shopify','pending_validation') FOR UPDATE`, [email, now]);
      }
      const registration = found.rows[0];
      if (!registration) return { duplicate: false, found: false };
      if (registration.shopify_customer_id && registration.shopify_customer_id !== customerId) {
        await client.query("UPDATE registrations SET status='failed', updated_at=$2 WHERE id=$1", [registration.id, now]);
        return { duplicate: false, found: true, conflict: true };
      }

      const updated = await client.query(`UPDATE registrations SET shopify_customer_id=$2,
        status='pending_validation', updated_at=$3 WHERE id=$1 RETURNING *`, [registration.id, customerId, now]);
      await client.query(`UPDATE registration_identity_claims SET
        claim_state='active', activated_at=COALESCE(activated_at,$2)
        WHERE registration_id=$1 AND claim_state='reserved'`, [registration.id, now]);
      await this.insertOutbox(client, registration.id, "sync_registration", now);
      return { duplicate: false, found: true, registration: mapRow(updated.rows[0]) };
    });
  }

  async insertOutbox(client, registrationId, operation, now) {
    await client.query(`INSERT INTO outbox (id, registration_id, operation, next_attempt_at, created_at)
      VALUES ($1,$2,$3,$4,$4) ON CONFLICT (registration_id, operation) WHERE processed_at IS NULL DO NOTHING`,
    [this.idFactory(), registrationId, operation, now]);
  }

  async requestAdminOperation({ action, registrationId, customerId, now }) {
    return this.transaction(async (client) => {
      const result = await client.query(`SELECT * FROM registrations WHERE
        ($1::uuid IS NOT NULL AND id=$1) OR ($2::text IS NOT NULL AND shopify_customer_id=$2) FOR UPDATE`,
      [registrationId || null, customerId || null]);
      const registration = result.rows[0];
      if (!registration) throw new AppError("registration_not_found", 404);
      if (action === "approve") {
        if (registration.status === "approved") return { registration: mapRow(registration), idempotent: true };
        const cnpjClaim = await client.query(`SELECT 1 FROM registration_identity_claims
          WHERE registration_id=$1 AND identity_type='cnpj' AND claim_state <> 'released'`, [registration.id]);
        if (!registration.cnpj_normalized && !cnpjClaim.rowCount) throw new AppError("missing_cnpj", 409);
        if (registration.fiscal_status !== "ATIVA") throw new AppError("cnpj_not_validated", 409);
        if (!registration.shopify_customer_id || !registration.sync_completed_at || registration.status !== "pending_review") {
          throw new AppError("registration_not_ready", 409);
        }
        await this.insertOutbox(client, registration.id, "approve_registration", now);
      } else {
        if (registration.status === "rejected") return { registration: mapRow(registration), idempotent: true };
        if (!registration.shopify_customer_id) {
          const rejected = await client.query("UPDATE registrations SET status='rejected', updated_at=$2 WHERE id=$1 RETURNING *", [registration.id, now]);
          return { registration: mapRow(rejected.rows[0]), idempotent: false, completed: true };
        }
        await this.insertOutbox(client, registration.id, "reject_registration", now);
      }
      return { registration: mapRow(registration), idempotent: false, completed: false };
    });
  }

  async claimOutbox({ workerId, now }) {
    return this.transaction(async (client) => {
      const result = await client.query(`SELECT o.*, row_to_json(r.*) AS registration
        FROM outbox o JOIN registrations r ON r.id=o.registration_id
        WHERE o.processed_at IS NULL AND o.next_attempt_at <= $1
          AND (o.locked_at IS NULL OR o.locked_at < $1 - interval '5 minutes')
        ORDER BY o.next_attempt_at, o.created_at FOR UPDATE OF o SKIP LOCKED LIMIT 1`, [now]);
      if (!result.rows[0]) return null;
      await client.query("UPDATE outbox SET locked_at=$2, locked_by=$3 WHERE id=$1", [result.rows[0].id, now, workerId]);
      return { ...result.rows[0], registration: mapRow(result.rows[0].registration) };
    });
  }

  async completeOutbox({ item, registrationStatus, syncCompleted = false, now, payloadNeededUntil, enqueueApprove = false }) {
    return this.transaction(async (client) => {
      await client.query(`UPDATE outbox SET processed_at=$2, locked_at=NULL, locked_by=NULL,
        last_error=NULL, error_code=NULL, error_category=NULL, upstream_status=NULL,
        error_recorded_at=NULL WHERE id=$1`, [item.id, now]);
      const result = await client.query(`UPDATE registrations SET status=$2,
        sync_completed_at=CASE WHEN $3 THEN $4 ELSE sync_completed_at END, updated_at=$4 WHERE id=$1 RETURNING *`,
      [item.registration_id, registrationStatus, syncCompleted, now]);
      if (syncCompleted) {
        await client.query(`UPDATE registration_identity_claims SET
          claim_state=CASE WHEN identity_type='cnpj' THEN 'tombstoned' ELSE 'active' END,
          activated_at=COALESCE(activated_at,$2), released_at=NULL
          WHERE registration_id=$1 AND claim_state <> 'released'`, [item.registration_id, now]);
        if (payloadNeededUntil) {
          await client.query(`UPDATE registration_operational_payloads SET needed_until=$2
            WHERE registration_id=$1 AND purged_at IS NULL`, [item.registration_id, payloadNeededUntil]);
        }
      }
      if (enqueueApprove) await this.insertOutbox(client, item.registration_id, "approve_registration", now);
      return mapRow(result.rows[0]);
    });
  }

  async failOutbox({ item, error, now, nextAttemptAt, terminal }) {
    return this.transaction(async (client) => {
      await client.query(`UPDATE outbox SET attempts=attempts+1, last_error=NULL,
        error_code=$2, error_category=$3, upstream_status=$4,
        error_recorded_at=$5::timestamptz, next_attempt_at=$6::timestamptz,
        locked_at=NULL, locked_by=NULL,
        processed_at=CASE WHEN $7::boolean THEN $5::timestamptz ELSE NULL::timestamptz END
        WHERE id=$1`,
      [item.id, error.code, error.category, error.upstreamStatus, now, nextAttemptAt, terminal]);
      if (terminal) await client.query("UPDATE registrations SET status='failed', updated_at=$2 WHERE id=$1", [item.registration_id, now]);
    });
  }

  async enqueueReconciliation(registrationId) {
    return this.transaction(async (client) => {
      const found = await client.query(`SELECT registration.id, registration.cnpj_normalized,
          registration.phone_e164, payload.purged_at, payload.registration_id AS payload_id
        FROM registrations registration
        LEFT JOIN registration_operational_payloads payload ON payload.registration_id=registration.id
        WHERE registration.id=$1`, [registrationId]);
      if (!found.rowCount) throw new AppError("registration_not_found", 404);
      const registration = found.rows[0];
      if ((!registration.payload_id || registration.purged_at)
        && !(registration.cnpj_normalized && registration.phone_e164)) {
        throw new AppError("payload_purged", 409);
      }
      await this.insertOutbox(client, registrationId, "reconcile_registration", this.clock());
    });
  }

  async getRegistration(id) {
    const result = await this.pool.query("SELECT * FROM registrations WHERE id=$1", [id]);
    return mapRow(result.rows[0]);
  }

  async getOperationalPayload(registrationId) {
    const result = await this.pool.query(`SELECT registration_id, ciphertext, nonce, auth_tag,
      encryption_key_version, needed_until, created_at, purged_at
      FROM registration_operational_payloads WHERE registration_id=$1`, [registrationId]);
    return mapRow(result.rows[0]);
  }

  async reportRetentionCandidates(config) {
    const result = await this.pool.query(`WITH release_candidates AS (
        SELECT registration.id
        FROM registrations registration
        WHERE registration.shopify_customer_id IS NULL
          AND (registration.retention_hold_until IS NULL OR registration.retention_hold_until <= $1)
          AND NOT EXISTS (SELECT 1 FROM outbox pending
            WHERE pending.registration_id=registration.id AND pending.processed_at IS NULL)
          AND (
            (registration.status IN ('failed','rejected')
              AND registration.updated_at + ($3::bigint * interval '1 millisecond') <= $1)
            OR (registration.status NOT IN ('failed','rejected')
              AND registration.expires_at + ($2::bigint * interval '1 millisecond') <= $1)
          )
      ), payload_candidates AS (
        SELECT payload.registration_id
        FROM registration_operational_payloads payload
        JOIN registrations registration ON registration.id=payload.registration_id
        WHERE payload.purged_at IS NULL
          AND (registration.retention_hold_until IS NULL OR registration.retention_hold_until <= $1)
          AND NOT EXISTS (SELECT 1 FROM outbox pending
            WHERE pending.registration_id=registration.id AND pending.processed_at IS NULL)
          AND (
            (registration.shopify_customer_id IS NOT NULL
              AND registration.sync_completed_at IS NOT NULL
              AND payload.needed_until <= $1)
            OR registration.id IN (SELECT id FROM release_candidates)
          )
      ), historical_candidates AS (
        SELECT run.id
        FROM historical_identity_import_runs run
        WHERE run.status IN ('failed','completed')
          AND run.completed_at <= $1 - ($4::bigint * interval '1 millisecond')
          AND NOT EXISTS (SELECT 1 FROM historical_identity_index_metadata metadata
            WHERE metadata.active_import_run_id=run.id)
          AND NOT EXISTS (SELECT 1 FROM historical_identity_members member
            WHERE member.first_import_run_id=run.id OR member.last_import_run_id=run.id)
          AND NOT EXISTS (SELECT 1 FROM historical_customer_identity_states state
            WHERE state.first_import_run_id=run.id OR state.last_import_run_id=run.id)
      ) SELECT
        (SELECT count(*)::integer FROM release_candidates) AS released_registrations,
        (SELECT count(*)::integer FROM registration_identity_claims claim
          WHERE claim.registration_id IN (SELECT id FROM release_candidates)
            AND claim.claim_state <> 'released') AS released_claims,
        (SELECT count(*)::integer FROM payload_candidates) AS purged_payloads,
        (SELECT count(*)::integer FROM outbox WHERE processed_at <= $1 - ($4::bigint * interval '1 millisecond')) AS deleted_outbox,
        (SELECT count(*)::integer FROM webhook_events WHERE processed_at <= $1 - ($4::bigint * interval '1 millisecond')) AS deleted_webhook_events,
        (SELECT count(*)::integer FROM fiscal_registry_cache WHERE expires_at <= $1) AS deleted_fiscal_cache,
        (SELECT count(*)::integer FROM registration_rate_limit_buckets WHERE expires_at <= $1) AS deleted_rate_limit_buckets,
        (SELECT count(*)::integer FROM registration_request_admissions WHERE expires_at <= $1) AS deleted_admissions,
        (SELECT count(*)::integer FROM historical_candidates) AS deleted_historical_runs`, [
      config.now, config.expiredUnlinkedMs, config.failedUnlinkedMs, config.operationalEventsMs,
    ]);
    return result.rows[0];
  }

  async applyRetentionBatch(config) {
    return this.transaction(async (client) => {
      const release = await client.query(`SELECT registration.id
        FROM registrations registration
        WHERE registration.shopify_customer_id IS NULL
          AND (registration.retention_hold_until IS NULL OR registration.retention_hold_until <= $1)
          AND NOT EXISTS (SELECT 1 FROM outbox pending
            WHERE pending.registration_id=registration.id AND pending.processed_at IS NULL)
          AND (
            (registration.status IN ('failed','rejected')
              AND registration.updated_at + ($3::bigint * interval '1 millisecond') <= $1)
            OR (registration.status NOT IN ('failed','rejected')
              AND registration.expires_at + ($2::bigint * interval '1 millisecond') <= $1)
          )
        ORDER BY registration.updated_at, registration.id
        FOR UPDATE OF registration SKIP LOCKED LIMIT $4`, [
        config.now, config.expiredUnlinkedMs, config.failedUnlinkedMs, config.batchSize,
      ]);
      const releaseIds = release.rows.map((row) => row.id);
      let releasedClaims = 0;
      if (releaseIds.length) {
        const claims = await client.query(`UPDATE registration_identity_claims SET
            claim_state='released', released_at=$2
          WHERE registration_id=ANY($1::uuid[]) AND claim_state <> 'released' RETURNING 1`, [releaseIds, config.now]);
        releasedClaims = claims.rowCount;
        await client.query(`UPDATE registrations SET
            status=CASE WHEN expires_at <= $2 THEN 'expired' ELSE status END,
            email_normalized=NULL, cnpj_normalized=NULL, phone_e164=NULL, updated_at=$2
          WHERE id=ANY($1::uuid[])`, [releaseIds, config.now]);
      }

      const linkedPayloads = await client.query(`SELECT payload.registration_id
        FROM registration_operational_payloads payload
        JOIN registrations registration ON registration.id=payload.registration_id
        WHERE payload.purged_at IS NULL
          AND registration.shopify_customer_id IS NOT NULL
          AND registration.sync_completed_at IS NOT NULL
          AND payload.needed_until <= $1
          AND (registration.retention_hold_until IS NULL OR registration.retention_hold_until <= $1)
          AND NOT EXISTS (SELECT 1 FROM outbox pending
            WHERE pending.registration_id=registration.id AND pending.processed_at IS NULL)
        ORDER BY payload.needed_until, payload.registration_id
        FOR UPDATE OF payload SKIP LOCKED LIMIT $2`, [config.now, config.batchSize]);
      const payloadIds = [...new Set([...releaseIds, ...linkedPayloads.rows.map((row) => row.registration_id)])];
      let purgedPayloads = 0;
      if (payloadIds.length) {
        const purged = await client.query(`UPDATE registration_operational_payloads SET
            ciphertext=NULL, nonce=NULL, auth_tag=NULL, purged_at=$2
          WHERE registration_id=ANY($1::uuid[]) AND purged_at IS NULL RETURNING 1`, [payloadIds, config.now]);
        purgedPayloads = purged.rowCount;
        await client.query(`UPDATE registrations SET
            email_normalized=NULL, cnpj_normalized=NULL, phone_e164=NULL
          WHERE id=ANY($1::uuid[])`, [payloadIds]);
      }

      const deleteBatch = async (table, condition, params) => {
        const result = await client.query(`WITH candidates AS (
            SELECT ctid FROM ${table} WHERE ${condition} LIMIT $${params.length + 1} FOR UPDATE SKIP LOCKED
          ) DELETE FROM ${table} target USING candidates
            WHERE target.ctid=candidates.ctid RETURNING 1`, [...params, config.batchSize]);
        return result.rowCount;
      };
      const operationalCutoff = new Date(config.now.getTime() - config.operationalEventsMs);
      const deletedOutbox = await deleteBatch("outbox", "processed_at <= $1", [operationalCutoff]);
      const deletedWebhooks = await deleteBatch("webhook_events", "processed_at <= $1", [operationalCutoff]);
      const deletedFiscal = await deleteBatch("fiscal_registry_cache", "expires_at <= $1", [config.now]);
      const deletedBuckets = await deleteBatch("registration_rate_limit_buckets", "expires_at <= $1", [config.now]);
      const deletedAdmissions = await deleteBatch("registration_request_admissions", "expires_at <= $1", [config.now]);

      const historical = await client.query(`SELECT run.id
        FROM historical_identity_import_runs run
        WHERE run.status IN ('failed','completed') AND run.completed_at <= $1
          AND NOT EXISTS (SELECT 1 FROM historical_identity_index_metadata metadata
            WHERE metadata.active_import_run_id=run.id)
          AND NOT EXISTS (SELECT 1 FROM historical_identity_members member
            WHERE member.first_import_run_id=run.id OR member.last_import_run_id=run.id)
          AND NOT EXISTS (SELECT 1 FROM historical_customer_identity_states state
            WHERE state.first_import_run_id=run.id OR state.last_import_run_id=run.id)
        ORDER BY run.completed_at, run.id
        FOR UPDATE OF run SKIP LOCKED LIMIT $2`, [operationalCutoff, config.batchSize]);
      const historicalIds = historical.rows.map((row) => row.id);
      if (historicalIds.length) {
        await client.query("DELETE FROM historical_identity_snapshot_members WHERE import_run_id=ANY($1::uuid[])", [historicalIds]);
        await client.query("DELETE FROM historical_customer_identity_snapshot_states WHERE import_run_id=ANY($1::uuid[])", [historicalIds]);
        await client.query("DELETE FROM historical_identity_import_runs WHERE id=ANY($1::uuid[])", [historicalIds]);
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
        deleted_historical_runs: historicalIds.length,
      };
    });
  }

  async setSimulationPhone(customerId, phone) {
    await this.pool.query(`INSERT INTO simulation_shopify_customers (customer_id, phone_e164)
      VALUES ($1,$2) ON CONFLICT (customer_id) DO UPDATE SET phone_e164=EXCLUDED.phone_e164, updated_at=now()`, [customerId, phone]);
  }

  async setSimulationMetafields(customerId, fields) {
    const values = Object.fromEntries(fields.map((field) => [field.key, { value: String(field.value), type: field.type }]));
    await this.pool.query(`INSERT INTO simulation_shopify_customers (customer_id, metafields)
      VALUES ($1,$2::jsonb) ON CONFLICT (customer_id) DO UPDATE
      SET metafields=simulation_shopify_customers.metafields || EXCLUDED.metafields, updated_at=now()`, [customerId, JSON.stringify(values)]);
  }

  async addSimulationTags(customerId, tags) {
    await this.pool.query(`INSERT INTO simulation_shopify_customers (customer_id, tags)
      VALUES ($1,$2::text[]) ON CONFLICT (customer_id) DO UPDATE
      SET tags=ARRAY(SELECT DISTINCT unnest(simulation_shopify_customers.tags || EXCLUDED.tags)), updated_at=now()`, [customerId, tags]);
  }

  async removeSimulationTags(customerId, tags) {
    await this.pool.query(`INSERT INTO simulation_shopify_customers (customer_id) VALUES ($1)
      ON CONFLICT (customer_id) DO UPDATE SET
      tags=ARRAY(SELECT tag FROM unnest(simulation_shopify_customers.tags) AS tag WHERE NOT (tag = ANY($2::text[]))), updated_at=now()`, [customerId, tags]);
  }

  async getSimulationCustomer(customerId) {
    const result = await this.pool.query("SELECT * FROM simulation_shopify_customers WHERE customer_id=$1", [customerId]);
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.customer_id,
      phone: row.phone_e164,
      tags: row.tags,
      metafields: { nodes: Object.entries(row.metafields).map(([key, field]) => ({ key, ...field })) },
    };
  }

  async close() { await this.pool.end(); }
}
