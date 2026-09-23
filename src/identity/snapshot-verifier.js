import { isHistoricalIdentityShopDomain } from "./historical-identities.js";

const LOCAL_DATABASE_HOSTS = new Set(["localhost", "127.0.0.1"]);

const integer = (value) => Number.parseInt(value ?? "0", 10) || 0;

export class PostImportVerificationError extends Error {
  constructor(options = {}) {
    super("historical_identity_post_import_verification_failed", options);
    this.name = "PostImportVerificationError";
    this.code = "historical_identity_post_import_verification_failed";
    this.importPromoted = true;
    this.repeatImport = false;
    this.recoveryCommand = "npm run verify:historical-identities";
  }
}

export async function runImportWithPostVerification({ executeImport, verifySnapshot }) {
  const importSummary = await executeImport();
  try {
    const verification = await verifySnapshot();
    return { import: importSummary, post_import_verification: verification };
  } catch (cause) {
    throw new PostImportVerificationError({ cause });
  }
}

export function loadHistoricalIdentityVerificationConfig(env = process.env) {
  const databaseUrl = env.DATABASE_URL;
  if (typeof databaseUrl !== "string" || !databaseUrl) {
    throw new Error("identity_verification_database_required");
  }
  let parsed;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    throw new Error("identity_verification_database_invalid");
  }
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  const confirmedDatabase = env.B2B_IDENTITY_VERIFICATION_CONFIRMED_DATABASE;
  const sslMode = parsed.searchParams.get("sslmode") || "";
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)
    || !LOCAL_DATABASE_HOSTS.has(parsed.hostname)
    || !databaseName
    || databaseName !== confirmedDatabase
    || String(env.DATABASE_SSL || "").toLowerCase() === "true"
    || !["", "disable"].includes(sslMode)
    || String(env.RENDER || "").toLowerCase() === "true"
    || /render/i.test(`${parsed.hostname}/${databaseName}`)) {
    throw new Error("identity_verification_local_database_required");
  }
  const shopDomain = env.B2B_IDENTITY_VERIFICATION_SHOP_DOMAIN;
  if (!isHistoricalIdentityShopDomain(shopDomain, { allowSynthetic: true })) {
    throw new Error("identity_verification_shop_invalid");
  }
  return { databaseUrl, databaseName, shopDomain };
}

export async function verifyActiveHistoricalIdentitySnapshot({ pool, shopDomain }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const runs = await client.query(`SELECT
        count(*) FILTER (WHERE status='completed')::integer AS completed,
        count(*) FILTER (WHERE status='failed')::integer AS failed,
        count(*) FILTER (WHERE status='staging')::integer AS staging,
        count(*) FILTER (WHERE status='running')::integer AS legacy_running
      FROM historical_identity_import_runs WHERE shop_domain=$1`, [shopDomain]);
    const active = await client.query(`SELECT
        count(*)::integer AS active_snapshots,
        max(import_run.customers_scanned)::integer AS customers_processed
      FROM historical_identity_index_metadata metadata
      JOIN historical_identity_import_runs import_run
        ON import_run.id=metadata.active_import_run_id
        AND import_run.shop_domain=metadata.shop_domain
        AND import_run.status='completed'
      WHERE metadata.shop_domain=$1`, [shopDomain]);
    const registrations = await client.query("SELECT count(*)::integer AS count FROM registrations");
    const states = await client.query(`SELECT state.identity_type, state.validity, count(*)::integer AS count
      FROM historical_customer_identity_snapshot_states state
      JOIN historical_identity_index_metadata metadata
        ON metadata.shop_domain=state.shop_domain
        AND metadata.active_import_run_id=state.import_run_id
      WHERE state.shop_domain=$1
      GROUP BY state.identity_type, state.validity
      ORDER BY state.identity_type, state.validity`, [shopDomain]);
    const members = await client.query(`SELECT member.identity_type, count(*)::integer AS count
      FROM historical_identity_snapshot_members member
      JOIN historical_identity_index_metadata metadata
        ON metadata.shop_domain=member.shop_domain
        AND metadata.active_import_run_id=member.import_run_id
      WHERE member.shop_domain=$1
      GROUP BY member.identity_type
      ORDER BY member.identity_type`, [shopDomain]);
    const claims = await client.query(`SELECT identity_type, claim_state,
        count(*)::integer AS groups, sum(customer_count)::integer AS members
      FROM historical_identity_claims WHERE shop_domain=$1
      GROUP BY identity_type, claim_state
      ORDER BY identity_type, claim_state`, [shopDomain]);
    const columns = await client.query(`SELECT column_name FROM information_schema.columns
      WHERE table_schema=current_schema() AND table_name = ANY($1::text[])`, [[
      "historical_customer_identity_states",
      "historical_identity_members",
      "historical_customer_identity_snapshot_states",
      "historical_identity_snapshot_members",
    ]]);
    const plaintextColumns = columns.rows.filter(({ column_name: columnName }) => (
      /(^|_)(email|cnpj|phone)(_|$)|normalized|plaintext|raw_value/i.test(columnName)
    )).length;
    const runCounts = Object.fromEntries(Object.entries(runs.rows[0] || {})
      .map(([key, value]) => [key, integer(value)]));
    const summary = {
      runs: runCounts,
      active_snapshots: integer(active.rows[0]?.active_snapshots),
      customers_processed: integer(active.rows[0]?.customers_processed),
      registrations: integer(registrations.rows[0]?.count),
      states: states.rows.map((row) => ({ ...row, count: integer(row.count) })),
      members: members.rows.map((row) => ({ ...row, count: integer(row.count) })),
      claims: claims.rows.map((row) => ({
        ...row, groups: integer(row.groups), members: integer(row.members),
      })),
      plaintext_identifier_columns: plaintextColumns,
    };
    if (summary.active_snapshots !== 1 || summary.plaintext_identifier_columns !== 0) {
      throw new Error("historical_identity_snapshot_invalid");
    }
    await client.query("COMMIT");
    return summary;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

export async function runHistoricalIdentityVerificationCommand({ env, PoolClass, stdout }) {
  const config = loadHistoricalIdentityVerificationConfig(env);
  const pool = new PoolClass({ connectionString: config.databaseUrl, ssl: false });
  try {
    const summary = await verifyActiveHistoricalIdentitySnapshot({
      pool,
      shopDomain: config.shopDomain,
    });
    stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return summary;
  } finally {
    await pool.end();
  }
}
