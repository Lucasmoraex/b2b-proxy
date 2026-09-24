import assert from "node:assert/strict";
import { test } from "node:test";
import {
  loadHistoricalIdentityVerificationConfig,
  runImportWithPostVerification,
} from "../src/identity/snapshot-verifier.js";

const LOCAL_URL = "postgres://local-user@127.0.0.1:5432/elements_b2b_v2_identity_validation";
const SHOP = "synthetic-verification.myshopify.com";

test("DB-only verification config never reads Shopify credentials", () => {
  const values = {
    DATABASE_URL: LOCAL_URL,
    DATABASE_SSL: "false",
    B2B_IDENTITY_VERIFICATION_CONFIRMED_DATABASE: "elements_b2b_v2_identity_validation",
    B2B_IDENTITY_VERIFICATION_SHOP_DOMAIN: SHOP,
  };
  const env = new Proxy(values, {
    get(target, property) {
      if (property === "SHOPIFY_ADMIN_TOKEN") throw new Error("verification_must_not_read_shopify_token");
      return target[property];
    },
  });
  const config = loadHistoricalIdentityVerificationConfig(env);
  assert.equal(config.databaseName, "elements_b2b_v2_identity_validation");
  assert.equal(config.shopDomain, SHOP);
});

test("DB-only verification rejects remote, Render, SSL and unconfirmed databases", () => {
  const base = {
    DATABASE_URL: LOCAL_URL,
    DATABASE_SSL: "false",
    B2B_IDENTITY_VERIFICATION_CONFIRMED_DATABASE: "elements_b2b_v2_identity_validation",
    B2B_IDENTITY_VERIFICATION_SHOP_DOMAIN: SHOP,
  };
  assert.throws(() => loadHistoricalIdentityVerificationConfig({
    ...base, DATABASE_URL: "postgres://user@remote.example.invalid/elements_b2b_v2_identity_validation",
  }), /identity_verification_local_database_required/);
  assert.throws(() => loadHistoricalIdentityVerificationConfig({
    ...base, DATABASE_SSL: "true",
  }), /identity_verification_local_database_required/);
  assert.throws(() => loadHistoricalIdentityVerificationConfig({
    ...base, RENDER: "true",
  }), /identity_verification_local_database_required/);
  assert.throws(() => loadHistoricalIdentityVerificationConfig({
    ...base, B2B_IDENTITY_VERIFICATION_CONFIRMED_DATABASE: "different_database",
  }), /identity_verification_local_database_required/);
});

test("post-import report failure says promotion already happened and never repeats import", async () => {
  let importExecutions = 0;
  await assert.rejects(runImportWithPostVerification({
    executeImport: async () => {
      importExecutions += 1;
      return { customers_scanned: 2 };
    },
    verifySnapshot: async () => { throw new Error("synthetic_report_failure"); },
  }), (error) => (
    error.code === "historical_identity_post_import_verification_failed"
    && error.importPromoted === true
    && error.repeatImport === false
    && error.recoveryCommand === "npm run verify:historical-identities"
  ));
  assert.equal(importExecutions, 1);
});
