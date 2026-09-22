import crypto from "node:crypto";
import { AppError } from "../errors.js";

const CONSTRAINT_ERRORS = {
  registrations_email_unique: "email_in_use",
  registrations_cnpj_unique: "cnpj_in_use",
  registrations_phone_unique: "phone_in_use",
  registrations_idempotency_unique: "idempotency_conflict",
  registrations_shopify_customer_unique: "shopify_customer_in_use",
};

const mapRow = (row) => row ? { ...row } : null;

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
          if (existing && new Date(existing.expires_at) > input.now) {
            if (existing.request_digest !== input.requestDigest) throw new AppError("idempotency_conflict", 409);
            return { registration: mapRow(existing), reused: true };
          }
          if (existing && existing.shopify_customer_id) throw new AppError("idempotency_conflict", 409);

          await client.query(`DELETE FROM registrations
            WHERE expires_at <= $1 AND shopify_customer_id IS NULL
              AND status IN ('reserved', 'pending_shopify', 'expired')`, [input.now]);

          const id = this.idFactory();
          const result = await client.query(`INSERT INTO registrations (
              id, email_normalized, cnpj_normalized, phone_e164, status,
              idempotency_key, request_digest, fiscal_status, fiscal_validated_at,
              expires_at, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,'reserved',$5,$6,$7,$8,$9,$8,$8)
            RETURNING *`, [
            id, input.email, input.cnpj, input.phone, input.idempotencyKey,
            input.requestDigest, input.fiscalStatus, input.now, input.expiresAt,
          ]);
          return { registration: mapRow(result.rows[0]), reused: false };
        }, "SERIALIZABLE");
      } catch (error) {
        if (error.code === "40001" && attempt < 2) continue;
        throw error;
      }
    }
    throw new AppError("internal_error", 500);
  }

  async findByIdempotencyKey(idempotencyKey) {
    const result = await this.pool.query("SELECT * FROM registrations WHERE idempotency_key=$1", [idempotencyKey]);
    return mapRow(result.rows[0]);
  }

  async associateWebhook({ eventId, topic, payloadDigest, email, customerId, now }) {
    return this.transaction(async (client) => {
      const inserted = await client.query(`INSERT INTO webhook_events (event_id, topic, payload_digest, processed_at)
        VALUES ($1,$2,$3,$4) ON CONFLICT (event_id) DO NOTHING RETURNING event_id`, [eventId, topic, payloadDigest, now]);
      if (!inserted.rowCount) return { duplicate: true };

      const found = await client.query(`SELECT * FROM registrations
        WHERE email_normalized = $1 AND expires_at > $2
          AND status IN ('reserved','pending_shopify','pending_validation') FOR UPDATE`, [email, now]);
      const registration = found.rows[0];
      if (!registration) return { duplicate: false, found: false };
      if (registration.shopify_customer_id && registration.shopify_customer_id !== customerId) {
        await client.query("UPDATE registrations SET status='failed', updated_at=$2 WHERE id=$1", [registration.id, now]);
        return { duplicate: false, found: true, conflict: true };
      }

      const updated = await client.query(`UPDATE registrations SET shopify_customer_id=$2,
        status='pending_validation', updated_at=$3 WHERE id=$1 RETURNING *`, [registration.id, customerId, now]);
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
        if (!registration.cnpj_normalized) throw new AppError("missing_cnpj", 409);
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

  async completeOutbox({ item, registrationStatus, syncCompleted = false, now, enqueueApprove = false }) {
    return this.transaction(async (client) => {
      await client.query("UPDATE outbox SET processed_at=$2, locked_at=NULL, locked_by=NULL, last_error=NULL WHERE id=$1", [item.id, now]);
      const result = await client.query(`UPDATE registrations SET status=$2,
        sync_completed_at=CASE WHEN $3 THEN $4 ELSE sync_completed_at END, updated_at=$4 WHERE id=$1 RETURNING *`,
      [item.registration_id, registrationStatus, syncCompleted, now]);
      if (enqueueApprove) await this.insertOutbox(client, item.registration_id, "approve_registration", now);
      return mapRow(result.rows[0]);
    });
  }

  async failOutbox({ item, error, now, nextAttemptAt, terminal }) {
    return this.transaction(async (client) => {
      await client.query(`UPDATE outbox SET attempts=attempts+1, last_error=$2,
        next_attempt_at=$3, locked_at=NULL, locked_by=NULL, processed_at=CASE WHEN $4 THEN $5 ELSE NULL END WHERE id=$1`,
      [item.id, error, nextAttemptAt, terminal, now]);
      if (terminal) await client.query("UPDATE registrations SET status='failed', updated_at=$2 WHERE id=$1", [item.registration_id, now]);
    });
  }

  async enqueueReconciliation(registrationId) {
    return this.transaction(async (client) => {
      const found = await client.query("SELECT id FROM registrations WHERE id=$1", [registrationId]);
      if (!found.rowCount) throw new AppError("registration_not_found", 404);
      await this.insertOutbox(client, registrationId, "reconcile_registration", this.clock());
    });
  }

  async getRegistration(id) {
    const result = await this.pool.query("SELECT * FROM registrations WHERE id=$1", [id]);
    return mapRow(result.rows[0]);
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
