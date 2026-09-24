import crypto from "node:crypto";
import pg from "pg";
import { loadConfig } from "../src/config.js";
import { createPiiEncryptionKeyring, decryptRegistrationOperationalPayload } from "../src/pii-crypto.js";
import { RetentionService, RETENTION_EXECUTION_CONFIRMATION } from "../src/retention.js";
import { assertSimulationSafety } from "../src/simulation.js";
import { PostgresRegistrationStore } from "../src/storage/postgres-store.js";

const EXPECTED_DATABASE = "elements_b2b_v2_release_validation";
const EXPECTED_CONFIRMATION = "VALIDATE_LOCAL_RELEASE_CANDIDATE";
const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost"]);

const assertSafeTarget = (config) => {
  if (process.env.B2B_RELEASE_VALIDATION_CONFIRMATION !== EXPECTED_CONFIRMATION) {
    throw new Error("release_validation_confirmation_required");
  }
  assertSimulationSafety(config, { role: "web" });
  if (!config.simulationMode || config.shop !== "simulation.example.invalid") {
    throw new Error("release_validation_simulation_required");
  }
  if (config.shopifyToken || config.shopifyClientId || config.shopifyClientSecret || config.registryToken) {
    throw new Error("release_validation_external_credentials_forbidden");
  }
  const database = new URL(config.databaseUrl);
  if (!LOCAL_HOSTS.has(database.hostname)
    || decodeURIComponent(database.pathname.slice(1)) !== EXPECTED_DATABASE
    || config.databaseSsl) {
    throw new Error("release_validation_local_database_required");
  }
  const api = new URL(process.env.B2B_RELEASE_VALIDATION_API_URL || "");
  if (!LOCAL_HOSTS.has(api.hostname) || api.protocol !== "http:") {
    throw new Error("release_validation_local_api_required");
  }
  return api;
};

const makeCnpj = (base) => {
  const digit = (value) => {
    let sum = 0;
    let factor = value.length - 7;
    for (const character of value) {
      sum += Number(character) * factor;
      factor -= 1;
      if (factor < 2) factor = 9;
    }
    const remainder = sum % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };
  const first = digit(base);
  return `${base}${first}${digit(`${base}${first}`)}`;
};

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const main = async () => {
  const config = loadConfig();
  const api = assertSafeTarget(config);
  const pool = new pg.Pool({ connectionString: config.databaseUrl, ssl: false });
  const store = new PostgresRegistrationStore({ pool });
  const piiKeyring = createPiiEncryptionKeyring({
    activeVersion: config.piiEncryptionActiveKeyVersion,
    serializedKeys: config.piiEncryptionKeys,
    otherSecrets: [
      config.adminSecret, config.registrationTokenSecret, config.shopifyWebhookSecret,
      config.dataDigestSecret, config.rateLimitKeySecret,
    ],
  });
  const request = async (path, { method = "GET", headers = {}, body } = {}) => {
    const response = await fetch(new URL(path, api), {
      method,
      headers: { Origin: "http://localhost:4173", ...headers },
      body,
    });
    let parsed = null;
    try { parsed = await response.json(); } catch { parsed = null; }
    return { status: response.status, body: parsed };
  };
  const postRegistration = (payload) => request("/v1/registrations", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
    body: JSON.stringify(payload),
  });

  const fixture = {
    email: "release-candidate@example.invalid",
    cnpj: makeCnpj("763456789012"),
    phone: "+5511999998101",
  };
  try {
    const health = await request("/health");
    if (health.status !== 200 || health.body?.ok !== true) throw new Error("release_health_failed");

    const accepted = await postRegistration(fixture);
    if (accepted.status !== 201 || !accepted.body?.registration_id || !accepted.body?.registration_token) {
      throw new Error("release_registration_failed");
    }
    const registrationId = accepted.body.registration_id;
    const registrationToken = accepted.body.registration_token;

    const duplicates = {};
    const cases = [
      ["email", "email_in_use", { ...fixture, cnpj: makeCnpj("773456789012"), phone: "+5511999998102" }],
      ["cnpj", "cnpj_in_use", { ...fixture, email: "release-cnpj@example.invalid", phone: "+5511999998103" }],
      ["phone", "phone_in_use", { ...fixture, email: "release-phone@example.invalid", cnpj: makeCnpj("783456789012") }],
    ];
    for (const [type, code, payload] of cases) {
      const response = await postRegistration(payload);
      if (response.status !== 409 || response.body?.error?.code !== code) {
        throw new Error(`release_${type}_duplicate_failed`);
      }
      duplicates[type] = true;
    }

    const webhookBody = JSON.stringify({
      id: "synthetic-release-customer",
      email: fixture.email,
    });
    const webhookHmac = crypto.createHmac("sha256", config.shopifyWebhookSecret)
      .update(webhookBody)
      .digest("base64");
    const webhook = await request("/webhooks/shopify/customers-create", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Hmac-Sha256": webhookHmac,
        "X-Shopify-Webhook-Id": crypto.randomUUID(),
        "X-Shopify-Topic": "customers/create",
        "X-Shopify-Shop-Domain": "simulation.example.invalid",
      },
      body: webhookBody,
    });
    if (webhook.status !== 202 || webhook.body?.matched !== true) throw new Error("release_webhook_failed");

    const queued = await pool.query(`SELECT
        EXISTS(SELECT 1 FROM webhook_events WHERE topic='customers/create') AS webhook_recorded,
        EXISTS(SELECT 1 FROM outbox WHERE registration_id=$1 AND operation='sync_registration') AS outbox_recorded`,
    [registrationId]);
    if (!queued.rows[0].webhook_recorded || !queued.rows[0].outbox_recorded) {
      throw new Error("release_outbox_not_recorded");
    }

    let synchronized = null;
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
      const state = await pool.query(`SELECT status, sync_completed_at,
          EXISTS(SELECT 1 FROM outbox WHERE registration_id=$1 AND operation='sync_registration'
            AND processed_at IS NOT NULL) AS outbox_processed
        FROM registrations WHERE id=$1`, [registrationId]);
      synchronized = state.rows[0];
      if (synchronized?.status === "pending_review"
        && synchronized.sync_completed_at && synchronized.outbox_processed) break;
      await sleep(200);
    }
    if (synchronized?.status !== "pending_review"
      || !synchronized.sync_completed_at || !synchronized.outbox_processed) {
      throw new Error("release_worker_sync_failed");
    }

    const claims = await pool.query(`SELECT identity_type, claim_state
      FROM registration_identity_claims WHERE registration_id=$1 ORDER BY identity_type`, [registrationId]);
    const states = Object.fromEntries(claims.rows.map((claim) => [claim.identity_type, claim.claim_state]));
    if (states.cnpj !== "tombstoned" || states.email !== "active" || states.phone !== "active") {
      throw new Error("release_claim_transition_failed");
    }

    const payload = await store.getOperationalPayload(registrationId);
    const decrypted = decryptRegistrationOperationalPayload({
      registrationId, encrypted: payload, keyring: piiKeyring,
    });
    if (JSON.stringify(decrypted) !== JSON.stringify(fixture)) throw new Error("release_payload_decryption_failed");

    const future = new Date(new Date(payload.needed_until).getTime() + 1);
    const retentionConfig = {
      now: future,
      enabled: false,
      mode: "report-only",
      confirmation: "",
      environment: "staging",
      allowProduction: false,
      expiredUnlinkedMs: 1000,
      syncedPayloadMs: 1000,
      failedUnlinkedMs: 1000,
      operationalEventsMs: 30 * 24 * 60 * 60 * 1000,
      batchSize: 50,
    };
    const retention = new RetentionService({ store, clock: () => future });
    const beforeReport = await pool.query(`SELECT xmin::text, purged_at,
      octet_length(ciphertext) AS ciphertext_length FROM registration_operational_payloads
      WHERE registration_id=$1`, [registrationId]);
    const report = await retention.run(retentionConfig);
    const afterReport = await pool.query(`SELECT xmin::text, purged_at,
      octet_length(ciphertext) AS ciphertext_length FROM registration_operational_payloads
      WHERE registration_id=$1`, [registrationId]);
    if (report.purged_payloads !== 1
      || JSON.stringify(beforeReport.rows[0]) !== JSON.stringify(afterReport.rows[0])) {
      throw new Error("release_retention_report_mutated_data");
    }

    const purge = await retention.run({
      ...retentionConfig,
      enabled: true,
      mode: "execute",
      confirmation: RETENTION_EXECUTION_CONFIRMATION,
    });
    if (purge.purged_payloads !== 1) throw new Error("release_synthetic_purge_failed");
    const purged = await store.getOperationalPayload(registrationId);
    if (!purged.purged_at || purged.ciphertext || purged.nonce || purged.auth_tag) {
      throw new Error("release_payload_not_purged");
    }

    const cnpjAfterPurge = await postRegistration({
      email: "release-after-purge@example.invalid",
      cnpj: fixture.cnpj,
      phone: "+5511999998104",
    });
    if (cnpjAfterPurge.status !== 409 || cnpjAfterPurge.body?.error?.code !== "cnpj_in_use") {
      throw new Error("release_tombstone_not_blocking");
    }

    const expiresAt = new Date(accepted.body.expires_at).getTime();
    if (Date.now() <= expiresAt) await sleep(expiresAt - Date.now() + 20);
    const expiredToken = await request(`/v1/registrations/${registrationId}`, {
      headers: { Authorization: `Bearer ${registrationToken}` },
    });
    if (expiredToken.status !== 401 || expiredToken.body?.error?.code !== "unauthorized") {
      throw new Error("release_expired_token_not_rejected");
    }

    const simulation = await pool.query(`SELECT
        phone_e164 IS NOT NULL AS has_phone,
        tags @> ARRAY['b2b-pending']::text[] AS has_pending_tag,
        metafields ? 'cnpj' AS has_cnpj_metafield,
        metafields ? 'cnpj_status' AS has_status_metafield
      FROM simulation_shopify_customers WHERE customer_id='synthetic-release-customer'`);
    if (!simulation.rowCount || !Object.values(simulation.rows[0]).every(Boolean)) {
      throw new Error("release_simulated_projection_failed");
    }

    process.stdout.write(`${JSON.stringify({
      ok: true,
      health: true,
      registration_accepted: true,
      duplicate_conflicts: duplicates,
      webhook_hmac_validated: true,
      webhook_recorded: true,
      outbox_recorded: true,
      worker_processed: true,
      sync_completed: true,
      claim_states: states,
      aes_gcm_decrypted: true,
      retention_report_only_unchanged: true,
      synthetic_payload_purged: true,
      cnpj_blocked_after_purge: true,
      expired_token_status: expiredToken.status,
      external_calls: 0,
    }, null, 2)}\n`);
  } finally {
    await pool.end();
  }
};

await main();
