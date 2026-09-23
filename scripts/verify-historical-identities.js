import pg from "pg";
import { runHistoricalIdentityVerificationCommand } from "../src/identity/snapshot-verifier.js";

try {
  await runHistoricalIdentityVerificationCommand({
    env: process.env,
    PoolClass: pg.Pool,
    stdout: process.stdout,
  });
} catch (error) {
  const known = new Set([
    "identity_verification_database_required",
    "identity_verification_database_invalid",
    "identity_verification_local_database_required",
    "identity_verification_shop_invalid",
    "historical_identity_snapshot_invalid",
  ]);
  const candidate = error?.code || error?.message;
  process.stderr.write(`${JSON.stringify({
    level: "error",
    event: "historical_identity_db_only_verification_failed",
    code: known.has(candidate) ? candidate : "internal_error",
  })}\n`);
  process.exitCode = 1;
}
