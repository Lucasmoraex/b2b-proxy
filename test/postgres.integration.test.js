import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { test } from "node:test";
import pg from "pg";
import { PostgresRegistrationStore } from "../src/storage/postgres-store.js";
import { makeCnpj } from "./helpers.js";

const testDatabaseUrl = process.env.TEST_DATABASE_URL;

test("PostgreSQL enforces concurrent uniqueness in an isolated schema", { skip: !testDatabaseUrl }, async () => {
  const schema = `b2b_test_${crypto.randomUUID().replaceAll("-", "")}`;
  const admin = new pg.Pool({ connectionString: testDatabaseUrl });
  await admin.query(`CREATE SCHEMA "${schema}"`);
  const pool = new pg.Pool({ connectionString: testDatabaseUrl, options: `-c search_path=${schema}` });
  try {
    const migration = await fs.readFile(new URL("../migrations/001_secure_registrations.sql", import.meta.url), "utf8");
    await pool.query(migration);
    const store = new PostgresRegistrationStore({ pool });
    const now = new Date("2030-01-01T00:00:00.000Z");
    const base = {
      cnpj: makeCnpj(), phone: "+5511999990001", requestDigest: "a".repeat(64),
      fiscalStatus: "ATIVA", now, expiresAt: new Date(now.getTime() + 1800000),
    };
    const results = await Promise.allSettled([
      store.reserve({ ...base, email: "one@example.invalid", idempotencyKey: crypto.randomUUID() }),
      store.reserve({ ...base, email: "two@example.invalid", phone: "+5511999990002", idempotencyKey: crypto.randomUUID() }),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    const rejected = results.find((result) => result.status === "rejected");
    assert.equal(rejected.reason.code, "cnpj_in_use");
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
    await admin.end();
  }
});
