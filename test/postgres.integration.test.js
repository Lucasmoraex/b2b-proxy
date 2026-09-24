import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { test } from "node:test";
import pg from "pg";
import { DATA_DIGEST_VERSION } from "../src/data-digests.js";
import {
  buildHistoricalCustomerIdentityRecord,
  hashHistoricalIdentity,
  identityIndexSecretFingerprint,
  registrationIdentityClaims,
} from "../src/identity/historical-identities.js";
import { HistoricalIdentityImporter } from "../src/services/historical-identity-importer.js";
import {
  runImportWithPostVerification,
  verifyActiveHistoricalIdentitySnapshot,
} from "../src/identity/snapshot-verifier.js";
import { PostgresRegistrationStore } from "../src/storage/postgres-store.js";
import {
  hashClientIp,
  registrationAdmissionDigest,
  registrationRateLimitIdentityKeys,
} from "../src/rate-limit.js";
import { makeCnpj } from "./helpers.js";
import { persistedErrorRecord } from "../src/security.js";
import { buildRegistrationIdentityClaims } from "../src/registration-identities.js";
import { createPiiEncryptionKeyring, encryptRegistrationOperationalPayload } from "../src/pii-crypto.js";
import { RetentionService } from "../src/retention.js";

const testDatabaseUrl = process.env.TEST_DATABASE_URL;
const pages = async function* (...values) { for (const value of values) yield value; };

test("PostgreSQL migrations, indexed precheck, cache and concurrent uniqueness", { skip: !testDatabaseUrl }, async () => {
  const schema = `b2b_test_${crypto.randomUUID().replaceAll("-", "")}`;
  const admin = new pg.Pool({ connectionString: testDatabaseUrl });
  await admin.query(`CREATE SCHEMA "${schema}"`);
  const pool = new pg.Pool({ connectionString: testDatabaseUrl, options: `-c search_path=${schema}` });
  try {
    const migrationNames = (await fs.readdir(new URL("../migrations/", import.meta.url)))
      .filter((name) => name.endsWith(".sql"))
      .sort();
    for (const migrationName of migrationNames) {
      const migration = await fs.readFile(new URL(`../migrations/${migrationName}`, import.meta.url), "utf8");
      await pool.query(migration);
    }
    const store = new PostgresRegistrationStore({ pool });
    const now = new Date("2030-01-01T00:00:00.000Z");
    const base = {
      cnpj: makeCnpj(), phone: "+5511999990001", requestDigest: "a".repeat(64),
      requestDigestVersion: DATA_DIGEST_VERSION,
      fiscalStatus: "ATIVA", now, expiresAt: new Date(now.getTime() + 1800000),
    };
    const results = await Promise.allSettled([
      store.reserve({ ...base, email: "one@example.invalid", idempotencyKey: crypto.randomUUID() }),
      store.reserve({ ...base, email: "two@example.invalid", phone: "+5511999990002", idempotencyKey: crypto.randomUUID() }),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    const rejected = results.find((result) => result.status === "rejected");
    assert.equal(rejected.reason.code, "cnpj_in_use");

    const sharedPhone = "+5511999990080";
    const phoneResults = await Promise.allSettled([
      store.reserve({
        ...base, email: "phone-one@example.invalid", cnpj: makeCnpj("223456789012"),
        phone: sharedPhone, requestDigest: "b".repeat(64), idempotencyKey: crypto.randomUUID(),
      }),
      store.reserve({
        ...base, email: "phone-two@example.invalid", cnpj: makeCnpj("323456789012"),
        phone: sharedPhone, requestDigest: "c".repeat(64), idempotencyKey: crypto.randomUUID(),
      }),
    ]);
    assert.equal(phoneResults.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(phoneResults.find((result) => result.status === "rejected").reason.code, "phone_in_use");

    const winner = results.find((result) => result.status === "fulfilled").value.registration;
    assert.equal(winner.request_digest_version, DATA_DIGEST_VERSION);
    const conflict = await store.findConflict({
      email: "unused@example.invalid", cnpj: base.cnpj, phone: "+5511999990099", now,
    });
    assert.equal(conflict, "cnpj_in_use");

    const indexes = await pool.query(`SELECT indexname FROM pg_indexes
      WHERE schemaname=current_schema() AND tablename='registrations'`);
    const indexNames = new Set(indexes.rows.map((row) => row.indexname));
    assert.ok(indexNames.has("registrations_email_unique"));
    assert.ok(indexNames.has("registrations_cnpj_unique"));
    assert.ok(indexNames.has("registrations_phone_unique"));

    const rateSecret = "synthetic-postgres-rate-limit-key-secret-minimum-32";
    const dataDigestSecret = "synthetic-postgres-data-digest-secret-minimum-32";
    const rawIp = "203.0.113.77";
    const ipHash = hashClientIp(rawIp, rateSecret);
    const secondStore = new PostgresRegistrationStore({ pool });
    const quotaInput = (index, overrides = {}) => {
      const requestDigest = crypto.createHash("sha256").update(`request-${index}`).digest("hex");
      const identity = {
        email: `quota-${index}@example.invalid`,
        cnpj: makeCnpj(`${String(700000000000 + index).padStart(12, "0")}`),
        phone: `+55119888${String(90000 + index).slice(-5)}`,
      };
      return {
        idempotencyKey: crypto.randomUUID(),
        requestKeyDigest: registrationAdmissionDigest(requestDigest, dataDigestSecret),
        requestKeyDigestVersion: DATA_DIGEST_VERSION,
        ipHash,
        identityKeys: registrationRateLimitIdentityKeys({ ...identity, secret: rateSecret }),
        now,
        sharedWindowMs: 60_000,
        sharedMax: 3,
        identityWindowMs: 60_000,
        identityMax: 100,
        activeReservationsMax: 100,
        stateRetentionMs: 60_000,
        cleanupBatchSize: 50,
        ...overrides,
      };
    };
    const quotaResults = await Promise.allSettled(Array.from({ length: 12 }, (_, index) => (
      (index % 2 ? secondStore : store).consumeRegistrationQuota(quotaInput(index + 1))
    )));
    assert.equal(quotaResults.filter((result) => result.status === "fulfilled").length, 3);
    assert.equal(quotaResults.filter((result) => result.status === "rejected"
      && result.reason.code === "rate_limited").length, 9);

    const storedIpBuckets = await pool.query(`SELECT hit_count, key_hash
      FROM registration_rate_limit_buckets
      WHERE scope='registration_ip' AND key_hash=$1`, [ipHash]);
    assert.deepEqual(storedIpBuckets.rows.map((row) => row.hit_count), [3]);
    const persistedRateState = await pool.query(`SELECT
        (SELECT string_agg(key_hash::text, ',') FROM registration_rate_limit_buckets) AS bucket_keys,
        (SELECT string_agg(ip_key_hash::text, ',') FROM registration_request_admissions) AS admission_keys`);
    assert.equal(JSON.stringify(persistedRateState.rows).includes(rawIp), false);

    const admissionVersion = await pool.query(`SELECT request_key_digest_version
      FROM registration_request_admissions LIMIT 1`);
    assert.equal(admissionVersion.rows[0].request_key_digest_version, DATA_DIGEST_VERSION);

    const idempotentIpHash = hashClientIp("203.0.113.78", rateSecret);
    const idempotentKey = crypto.randomUUID();
    const idempotentInput = quotaInput(30, {
      idempotencyKey: idempotentKey,
      ipHash: idempotentIpHash,
      sharedMax: 1,
      identityMax: 1,
    });
    assert.equal((await store.consumeRegistrationQuota(idempotentInput)).reused, false);
    assert.equal((await secondStore.consumeRegistrationQuota(idempotentInput)).reused, true);
    const idempotentBucket = await pool.query(`SELECT hit_count FROM registration_rate_limit_buckets
      WHERE scope='registration_ip' AND key_hash=$1`, [idempotentIpHash]);
    assert.equal(idempotentBucket.rows[0].hit_count, 1);

    const repeatedIdentity = quotaInput(40, {
      ipHash: hashClientIp("203.0.113.79", rateSecret),
      sharedMax: 100,
      identityMax: 1,
    });
    await store.consumeRegistrationQuota(repeatedIdentity);
    await assert.rejects(secondStore.consumeRegistrationQuota({
      ...repeatedIdentity,
      idempotencyKey: crypto.randomUUID(),
      requestKeyDigest: registrationAdmissionDigest("f".repeat(64), dataDigestSecret),
      ipHash: hashClientIp("203.0.113.80", rateSecret),
    }), (error) => error.code === "rate_limited" && error.status === 429);

    const activeIpHash = hashClientIp("203.0.113.81", rateSecret);
    const activeReservationResults = await Promise.allSettled([
      store.reserve({
        ...base,
        email: "active-ip-one@example.invalid",
        cnpj: makeCnpj("713456789012"),
        phone: "+5511999990181",
        idempotencyKey: crypto.randomUUID(),
        requestDigest: "1".repeat(64),
        requestIpHash: activeIpHash,
        activeReservationsMax: 1,
      }),
      secondStore.reserve({
        ...base,
        email: "active-ip-two@example.invalid",
        cnpj: makeCnpj("813456789012"),
        phone: "+5511999990182",
        idempotencyKey: crypto.randomUUID(),
        requestDigest: "2".repeat(64),
        requestIpHash: activeIpHash,
        activeReservationsMax: 1,
      }),
    ]);
    assert.equal(activeReservationResults.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(activeReservationResults.filter((result) => result.status === "rejected"
      && result.reason.code === "rate_limited").length, 1);
    const storedRegistrationIp = await pool.query(`SELECT request_ip_hash
      FROM registrations WHERE request_ip_hash=$1`, [activeIpHash]);
    assert.equal(storedRegistrationIp.rowCount, 1);
    assert.equal(JSON.stringify(storedRegistrationIp.rows).includes("203.0.113.81"), false);

    const expiredQuotaInput = quotaInput(50, {
      now: new Date("2029-01-01T00:00:00.000Z"),
      stateRetentionMs: 1000,
      sharedWindowMs: 1000,
      identityWindowMs: 1000,
      ipHash: hashClientIp("203.0.113.82", rateSecret),
    });
    await store.consumeRegistrationQuota(expiredQuotaInput);
    const cleanup = await store.cleanupRegistrationAbuseState({
      now: new Date("2029-01-01T00:00:03.000Z"), batchSize: 50,
    });
    assert.ok(cleanup.buckets >= 4);
    assert.ok(cleanup.admissions >= 1);

    const expiredInput = {
      ...base,
      email: "expired@example.invalid",
      cnpj: makeCnpj("423456789012"),
      phone: "+5511999990081",
      idempotencyKey: crypto.randomUUID(),
      requestDigest: "d".repeat(64),
      now: new Date("2029-01-01T00:00:00.000Z"),
      expiresAt: new Date("2029-01-01T00:30:00.000Z"),
    };
    await store.reserve(expiredInput);
    assert.equal(await store.findConflict({
      email: expiredInput.email, cnpj: expiredInput.cnpj, phone: expiredInput.phone, now,
    }), null);
    const replacement = await store.reserve({
      ...expiredInput, idempotencyKey: crypto.randomUUID(), now,
      requestDigest: "e".repeat(64), expiresAt: new Date(now.getTime() + 1800000),
    });
    assert.equal(replacement.registration.email_normalized, expiredInput.email);

    await store.setFiscalCache({
      cnpj: winner.cnpj_normalized, found: true, active: true, status: "ATIVA",
      checkedAt: now, expiresAt: new Date(now.getTime() + 60_000),
    });
    assert.equal((await store.getFiscalCache(winner.cnpj_normalized, now)).status, "ATIVA");
    assert.equal(await store.getFiscalCache(winner.cnpj_normalized, new Date(now.getTime() + 60_000)), null);

    const webhookEventId = crypto.randomUUID();
    await store.associateWebhook({
      eventId: webhookEventId,
      topic: "customers/create",
      payloadDigest: "7".repeat(64),
      payloadDigestVersion: DATA_DIGEST_VERSION,
      email: winner.email_normalized,
      customerId: "gid://shopify/Customer/pg-structured-error",
      now,
    });
    const webhookVersion = await pool.query("SELECT payload_digest_version FROM webhook_events WHERE event_id=$1", [webhookEventId]);
    assert.equal(webhookVersion.rows[0].payload_digest_version, DATA_DIGEST_VERSION);
    const claimedOutbox = await store.claimOutbox({ workerId: "pg-test-worker", now });
    await store.failOutbox({
      item: claimedOutbox,
      error: persistedErrorRecord(Object.assign(new Error("private@example.invalid"), {
        code: "shopify_unavailable",
        upstreamStatus: 503,
      }), { defaultCategory: "shopify" }),
      now,
      nextAttemptAt: new Date(now.getTime() + 2000),
      terminal: false,
    });
    const structuredOutboxError = await pool.query(`SELECT last_error, error_code, error_category,
      upstream_status, error_recorded_at FROM outbox WHERE id=$1`, [claimedOutbox.id]);
    assert.equal(structuredOutboxError.rows[0].last_error, null);
    assert.equal(structuredOutboxError.rows[0].error_code, "shopify_unavailable");
    assert.equal(structuredOutboxError.rows[0].error_category, "shopify");
    assert.equal(structuredOutboxError.rows[0].upstream_status, 503);
    assert.ok(structuredOutboxError.rows[0].error_recorded_at);

    const historySecret = "synthetic-postgres-identity-index-secret-minimum-32";
    const historyShop = "synthetic-postgres.myshopify.com";
    const historicalCnpj = makeCnpj("523456789012");
    const historicalCustomers = [
      {
        id: "gid://shopify/Customer/pg-history-a", email: "pg-history-a@example.invalid",
        phone: "+5511999990111", note: null, cnpj: { value: historicalCnpj }, cjnpj: null,
      },
      {
        id: "gid://shopify/Customer/pg-history-b", email: "pg-history-b@example.invalid",
        phone: "+5511999990112", note: null, cnpj: { value: historicalCnpj }, cjnpj: null,
      },
    ];
    const importer = new HistoricalIdentityImporter({
      store, shopDomain: historyShop, identityIndexSecret: historySecret,
      clock: () => now,
    });
    await importer.run({
      pages: pages(historicalCustomers), dryRun: false,
      confirmation: "IMPORT_HISTORICAL_IDENTITIES",
    });
    await importer.run({
      pages: pages([historicalCustomers[0]]), dryRun: false,
      confirmation: "IMPORT_HISTORICAL_IDENTITIES",
    });
    const historicalHash = hashHistoricalIdentity({ type: "cnpj", normalized: historicalCnpj, secret: historySecret });
    const claim = await pool.query(`SELECT customer_count, claim_state FROM historical_identity_claims
      WHERE shop_domain=$1 AND identity_type='cnpj' AND value_hash=$2`, [historyShop, historicalHash]);
    assert.deepEqual(claim.rows[0], { customer_count: 2, claim_state: "conflicted" });
    const exactMembership = await pool.query(`SELECT count(*)::integer AS count
      FROM historical_identity_snapshot_members member
      JOIN historical_identity_index_metadata metadata
        ON metadata.shop_domain=member.shop_domain AND metadata.active_import_run_id=member.import_run_id
      WHERE member.shop_domain=$1 AND member.shopify_customer_id=$2
        AND member.identity_type='cnpj' AND member.value_hash=$3`,
    [historyShop, historicalCustomers[0].id, historicalHash]);
    assert.equal(exactMembership.rows[0].count, 1);
    assert.equal(await store.findHistoricalConflict({
      shopDomain: historyShop,
      secretFingerprint: identityIndexSecretFingerprint(historySecret),
      claims: registrationIdentityClaims({
        email: "unused-history@example.invalid", cnpj: historicalCnpj,
        phone: "+5511999990199", secret: historySecret,
      }),
    }), "cnpj_in_use");

    const raceInput = {
      email: "pg-race@example.invalid",
      cnpj: makeCnpj("623456789012"),
      phone: "+5511999990121",
    };
    const raceHistorical = {
      shopDomain: historyShop,
      secretFingerprint: identityIndexSecretFingerprint(historySecret),
      claims: registrationIdentityClaims({ ...raceInput, secret: historySecret }),
    };
    const raceCustomer = {
      id: "gid://shopify/Customer/pg-race", email: raceInput.email, phone: raceInput.phone,
      note: null, cnpj: { value: raceInput.cnpj }, cjnpj: null,
    };
    const raceResults = await Promise.allSettled([
      store.reserve({
        ...raceInput, idempotencyKey: crypto.randomUUID(), requestDigest: "f".repeat(64),
        requestDigestVersion: DATA_DIGEST_VERSION,
        fiscalStatus: "ATIVA", now, expiresAt: new Date(now.getTime() + 1800000),
        historicalIdentity: raceHistorical,
      }),
      importer.run({
        pages: pages([raceCustomer]), dryRun: false,
        confirmation: "IMPORT_HISTORICAL_IDENTITIES",
      }),
    ]);
    assert.equal(raceResults.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(raceResults.filter((result) => result.status === "rejected").length, 1);

    const failedShop = "synthetic-failed-snapshot.myshopify.com";
    const failedRunId = crypto.randomUUID();
    const failedCustomer = {
      id: "gid://shopify/Customer/pg-failed", email: "pg-failed@example.invalid",
      phone: "+5511999990131", note: null, cnpj: { value: makeCnpj("723456789012") }, cjnpj: null,
    };
    const secretFingerprint = identityIndexSecretFingerprint(historySecret);
    await store.beginHistoricalIdentityImport({ runId: failedRunId, shopDomain: failedShop, secretFingerprint, now });
    await store.importHistoricalIdentityPage({
      runId: failedRunId,
      shopDomain: failedShop,
      secretFingerprint,
      customers: [buildHistoricalCustomerIdentityRecord(failedCustomer, historySecret)],
      now,
    });
    await assert.rejects(store.findHistoricalConflict({
      shopDomain: failedShop,
      secretFingerprint,
      claims: registrationIdentityClaims({
        email: failedCustomer.email, cnpj: failedCustomer.cnpj.value,
        phone: failedCustomer.phone, secret: historySecret,
      }),
    }), (error) => error.code === "identity_index_unavailable" && error.status === 503);
    await store.failHistoricalIdentityImport({
      runId: failedRunId,
      error: persistedErrorRecord(Object.assign(new Error("synthetic_failure"), { code: "historical_identity_import_failed" }), { defaultCategory: "historical_identity" }),
      now,
    });
    const failedClaims = await pool.query("SELECT count(*)::integer AS count FROM historical_identity_claims WHERE shop_domain=$1", [failedShop]);
    assert.equal(failedClaims.rows[0].count, 0);
    const stagedRows = await pool.query(`SELECT count(*)::integer AS count
      FROM historical_identity_snapshot_members WHERE import_run_id=$1`, [failedRunId]);
    assert.equal(stagedRows.rows[0].count, 3);
    const structuredImportError = await pool.query(`SELECT last_error, error_code, error_category,
      upstream_status, error_recorded_at FROM historical_identity_import_runs WHERE id=$1`, [failedRunId]);
    assert.equal(structuredImportError.rows[0].last_error, null);
    assert.equal(structuredImportError.rows[0].error_code, "historical_identity_import_failed");
    assert.equal(structuredImportError.rows[0].error_category, "historical_identity");
    assert.equal(structuredImportError.rows[0].upstream_status, null);
    assert.ok(structuredImportError.rows[0].error_recorded_at);

    const promotionShop = "synthetic-promotion.myshopify.com";
    const promotionRunId = crypto.randomUUID();
    const lateCustomer = {
      id: "gid://shopify/Customer/pg-late", email: "pg-late@example.invalid",
      phone: "+5511999990132", note: null, cnpj: { value: makeCnpj("823456789012") }, cjnpj: null,
    };
    await store.beginHistoricalIdentityImport({
      runId: promotionRunId, shopDomain: promotionShop, secretFingerprint, now,
    });
    await store.importHistoricalIdentityPage({
      runId: promotionRunId,
      shopDomain: promotionShop,
      secretFingerprint,
      customers: [buildHistoricalCustomerIdentityRecord(lateCustomer, historySecret)],
      now,
    });
    await store.reserve({
      email: lateCustomer.email,
      cnpj: lateCustomer.cnpj.value,
      phone: lateCustomer.phone,
      idempotencyKey: crypto.randomUUID(),
      requestDigest: "9".repeat(64),
      requestDigestVersion: DATA_DIGEST_VERSION,
      fiscalStatus: "ATIVA",
      now,
      expiresAt: new Date(now.getTime() + 1800000),
    });
    await assert.rejects(store.completeHistoricalIdentityImport({
      runId: promotionRunId,
      shopDomain: promotionShop,
      secretFingerprint,
      identityIndexSecret: historySecret,
      summary: { pages_scanned: 1, customers_scanned: 1, claims_processed: 3, states_processed: 3 },
      now,
    }), /historical_identity_registration_conflict/);
    const unpromoted = await pool.query(`SELECT status FROM historical_identity_import_runs WHERE id=$1`, [promotionRunId]);
    assert.equal(unpromoted.rows[0].status, "staging");
    const promotionMetadata = await pool.query(`SELECT active_import_run_id
      FROM historical_identity_index_metadata WHERE shop_domain=$1`, [promotionShop]);
    assert.equal(promotionMetadata.rows[0].active_import_run_id, null);
    await store.failHistoricalIdentityImport({
      runId: promotionRunId,
      error: persistedErrorRecord(Object.assign(new Error("synthetic"), { code: "historical_identity_registration_conflict" }), { defaultCategory: "historical_identity" }),
      now,
    });

    const recoveryShop = "synthetic-verification-recovery.example.invalid";
    const recoveryImporter = new HistoricalIdentityImporter({
      store, shopDomain: recoveryShop, identityIndexSecret: historySecret, clock: () => now,
    });
    let recoveryImportExecutions = 0;
    await assert.rejects(runImportWithPostVerification({
      executeImport: async () => {
        recoveryImportExecutions += 1;
        return recoveryImporter.run({
          pages: pages([{
            id: "gid://shopify/Customer/verification-recovery",
            email: "verification-recovery@example.invalid",
            phone: "+5511999990133",
            note: null,
            cnpj: { value: makeCnpj("923456789012") },
            cjnpj: null,
          }]),
          dryRun: false,
          confirmation: "IMPORT_HISTORICAL_IDENTITIES",
        });
      },
      verifySnapshot: async () => { throw new Error("synthetic_post_import_report_failure"); },
    }), (error) => error.importPromoted === true && error.repeatImport === false);
    assert.equal(recoveryImportExecutions, 1);

    const persistedRun = await pool.query(`SELECT status, count(*)::integer AS count
      FROM historical_identity_import_runs WHERE shop_domain=$1 GROUP BY status`, [recoveryShop]);
    assert.deepEqual(persistedRun.rows, [{ status: "completed", count: 1 }]);
    const snapshotBefore = await pool.query(`SELECT
        (SELECT count(*)::integer FROM historical_identity_import_runs WHERE shop_domain=$1) AS runs,
        (SELECT count(*)::integer FROM historical_identity_index_metadata WHERE shop_domain=$1) AS metadata,
        (SELECT count(*)::integer FROM historical_customer_identity_snapshot_states WHERE shop_domain=$1) AS states,
        (SELECT count(*)::integer FROM historical_identity_snapshot_members WHERE shop_domain=$1) AS members`,
    [recoveryShop]);
    const recoveredSummary = await verifyActiveHistoricalIdentitySnapshot({ pool, shopDomain: recoveryShop });
    const snapshotAfter = await pool.query(`SELECT
        (SELECT count(*)::integer FROM historical_identity_import_runs WHERE shop_domain=$1) AS runs,
        (SELECT count(*)::integer FROM historical_identity_index_metadata WHERE shop_domain=$1) AS metadata,
        (SELECT count(*)::integer FROM historical_customer_identity_snapshot_states WHERE shop_domain=$1) AS states,
        (SELECT count(*)::integer FROM historical_identity_snapshot_members WHERE shop_domain=$1) AS members`,
    [recoveryShop]);
    assert.deepEqual(snapshotAfter.rows[0], snapshotBefore.rows[0]);
    assert.equal(recoveredSummary.active_snapshots, 1);
    assert.equal(recoveredSummary.customers_processed, 1);

    const piiKeyring = createPiiEncryptionKeyring({
      activeVersion: "pg-test-v1",
      serializedKeys: JSON.stringify({
        "pg-test-v1": Buffer.from("0123456789abcdef0123456789abcdef").toString("base64"),
      }),
    });
    const minimizedInput = (identity, overrides = {}) => {
      const registrationId = crypto.randomUUID();
      const registrationClaims = buildRegistrationIdentityClaims({ ...identity, secret: dataDigestSecret });
      const operationalPayload = encryptRegistrationOperationalPayload({
        registrationId, payload: identity, keyring: piiKeyring,
      });
      return {
        registrationId,
        ...identity,
        registrationClaims,
        operationalPayload: {
          ...operationalPayload,
          neededUntil: new Date(now.getTime() + 1000),
        },
        idempotencyKey: crypto.randomUUID(),
        requestDigest: crypto.randomBytes(32).toString("hex"),
        requestDigestVersion: DATA_DIGEST_VERSION,
        fiscalStatus: "ATIVA",
        now,
        expiresAt: new Date(now.getTime() + 1800000),
        ...overrides,
      };
    };
    const sharedMinimizedCnpj = makeCnpj("143456789012");
    const minimizedA = minimizedInput({
      email: "minimized-a@example.invalid", cnpj: sharedMinimizedCnpj, phone: "+5511999990141",
    });
    const minimizedB = minimizedInput({
      email: "minimized-b@example.invalid", cnpj: sharedMinimizedCnpj, phone: "+5511999990142",
    });
    const minimizedResults = await Promise.allSettled([
      store.reserve(minimizedA), secondStore.reserve(minimizedB),
    ]);
    assert.equal(minimizedResults.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(minimizedResults.find((result) => result.status === "rejected").reason.code, "cnpj_in_use");
    const minimizedWinnerInput = minimizedResults[0].status === "fulfilled" ? minimizedA : minimizedB;
    const minimizedWinner = minimizedResults.find((result) => result.status === "fulfilled").value.registration;
    assert.equal(minimizedWinner.email_normalized, null);
    assert.equal(minimizedWinner.cnpj_normalized, null);
    assert.equal(minimizedWinner.phone_e164, null);
    const persistedClaims = await pool.query(`SELECT identity_type, claim_state, value_hash
      FROM registration_identity_claims WHERE registration_id=$1 ORDER BY identity_type`, [minimizedWinner.id]);
    assert.equal(persistedClaims.rowCount, 3);
    assert.equal(JSON.stringify(persistedClaims.rows).includes(sharedMinimizedCnpj), false);
    const persistedPayload = await pool.query(`SELECT ciphertext, nonce, auth_tag, purged_at
      FROM registration_operational_payloads WHERE registration_id=$1`, [minimizedWinner.id]);
    assert.equal(persistedPayload.rowCount, 1);
    assert.equal(persistedPayload.rows[0].purged_at, null);

    const winnerEmailClaim = minimizedWinnerInput.registrationClaims.find((claim) => claim.type === "email");
    await store.associateWebhook({
      eventId: crypto.randomUUID(), topic: "customers/create",
      payloadDigest: "8".repeat(64), payloadDigestVersion: DATA_DIGEST_VERSION,
      email: minimizedWinnerInput.email, emailClaim: winnerEmailClaim,
      customerId: "gid://shopify/Customer/minimized-pg", now,
    });
    const minimizedOutbox = await pool.query(`SELECT id, registration_id FROM outbox
      WHERE registration_id=$1 AND processed_at IS NULL`, [minimizedWinner.id]);
    await store.completeOutbox({
      item: minimizedOutbox.rows[0], registrationStatus: "pending_review", syncCompleted: true,
      now, payloadNeededUntil: new Date(now.getTime() + 1000),
    });
    const retentionNow = new Date(now.getTime() + 2000);
    const retentionConfig = {
      now: retentionNow,
      mode: "report-only",
      enabled: false,
      confirmation: "",
      environment: "test",
      allowProduction: false,
      expiredUnlinkedMs: 1,
      syncedPayloadMs: 1000,
      failedUnlinkedMs: 1,
      operationalEventsMs: 10 * 365 * 24 * 60 * 60 * 1000,
      batchSize: 1,
    };
    const retentionService = new RetentionService({ store, clock: () => retentionNow });
    const report = await retentionService.run(retentionConfig);
    assert.ok(report.purged_payloads >= 1);
    assert.equal((await store.getOperationalPayload(minimizedWinner.id)).purged_at, null);
    const batches = await Promise.all([
      retentionService.run({ ...retentionConfig, mode: "execute", enabled: true, confirmation: "EXECUTE_B2B_RETENTION" }),
      retentionService.run({ ...retentionConfig, mode: "execute", enabled: true, confirmation: "EXECUTE_B2B_RETENTION" }),
    ]);
    assert.equal(batches.reduce((total, batch) => total + batch.purged_payloads, 0), 1);
    assert.ok((await store.getOperationalPayload(minimizedWinner.id)).purged_at);
    const tombstone = await pool.query(`SELECT claim_state FROM registration_identity_claims
      WHERE registration_id=$1 AND identity_type='cnpj'`, [minimizedWinner.id]);
    assert.equal(tombstone.rows[0].claim_state, "tombstoned");
    const alternateClaims = buildRegistrationIdentityClaims({
      email: "alternate-pg@example.invalid", cnpj: sharedMinimizedCnpj,
      phone: "+5511999990149", secret: dataDigestSecret,
    });
    assert.equal(await store.findConflict({
      email: "alternate-pg@example.invalid", cnpj: sharedMinimizedCnpj,
      phone: "+5511999990149", identityClaims: alternateClaims, now: retentionNow,
    }), "cnpj_in_use");
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
    await admin.end();
  }
});
