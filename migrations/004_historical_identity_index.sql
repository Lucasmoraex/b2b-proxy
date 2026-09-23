BEGIN;

CREATE TABLE IF NOT EXISTS historical_identity_index_metadata (
  shop_domain text PRIMARY KEY,
  secret_fingerprint char(64) NOT NULL,
  hash_algorithm text NOT NULL DEFAULT 'hmac-sha256-v1'
    CHECK (hash_algorithm = 'hmac-sha256-v1'),
  created_at timestamptz NOT NULL,
  verified_at timestamptz NOT NULL,
  CONSTRAINT historical_identity_metadata_shop_domain
    CHECK (shop_domain ~ '^[a-z0-9][a-z0-9-]*\.myshopify\.com$'),
  CONSTRAINT historical_identity_metadata_secret_fingerprint
    CHECK (secret_fingerprint ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS historical_identity_import_runs (
  id uuid PRIMARY KEY,
  shop_domain text NOT NULL,
  secret_fingerprint char(64) NOT NULL,
  status text NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  pages_scanned integer NOT NULL DEFAULT 0 CHECK (pages_scanned >= 0),
  customers_scanned integer NOT NULL DEFAULT 0 CHECK (customers_scanned >= 0),
  claims_processed integer NOT NULL DEFAULT 0 CHECK (claims_processed >= 0),
  states_processed integer NOT NULL DEFAULT 0 CHECK (states_processed >= 0),
  last_error text,
  CONSTRAINT historical_identity_runs_shop_domain
    CHECK (shop_domain ~ '^[a-z0-9][a-z0-9-]*\.myshopify\.com$'),
  CONSTRAINT historical_identity_runs_secret_fingerprint
    CHECK (secret_fingerprint ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS historical_identity_import_runs_shop_started_idx
  ON historical_identity_import_runs (shop_domain, started_at DESC);

CREATE TABLE IF NOT EXISTS historical_customer_identity_states (
  shop_domain text NOT NULL,
  shopify_customer_id text NOT NULL,
  identity_type text NOT NULL CHECK (identity_type IN ('email', 'cnpj', 'phone')),
  validity text NOT NULL CHECK (validity IN ('valid', 'invalid', 'incomplete')),
  sources text[] NOT NULL DEFAULT ARRAY[]::text[],
  first_imported_at timestamptz NOT NULL,
  last_imported_at timestamptz NOT NULL,
  first_import_run_id uuid NOT NULL REFERENCES historical_identity_import_runs(id),
  last_import_run_id uuid NOT NULL REFERENCES historical_identity_import_runs(id),
  PRIMARY KEY (shop_domain, shopify_customer_id, identity_type),
  CONSTRAINT historical_identity_states_customer_id_nonempty
    CHECK (length(shopify_customer_id) BETWEEN 1 AND 256)
);

CREATE INDEX IF NOT EXISTS historical_identity_states_run_idx
  ON historical_customer_identity_states (last_import_run_id);

CREATE TABLE IF NOT EXISTS historical_identity_members (
  shop_domain text NOT NULL,
  shopify_customer_id text NOT NULL,
  identity_type text NOT NULL CHECK (identity_type IN ('email', 'cnpj', 'phone')),
  value_hash char(64) NOT NULL,
  validity text NOT NULL DEFAULT 'valid' CHECK (validity = 'valid'),
  sources text[] NOT NULL DEFAULT ARRAY[]::text[],
  first_imported_at timestamptz NOT NULL,
  last_imported_at timestamptz NOT NULL,
  first_import_run_id uuid NOT NULL REFERENCES historical_identity_import_runs(id),
  last_import_run_id uuid NOT NULL REFERENCES historical_identity_import_runs(id),
  PRIMARY KEY (shop_domain, shopify_customer_id, identity_type, value_hash),
  CONSTRAINT historical_identity_members_hash_format
    CHECK (value_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT historical_identity_members_customer_id_nonempty
    CHECK (length(shopify_customer_id) BETWEEN 1 AND 256)
);

-- Deliberately non-unique: historical duplicates must remain representable.
CREATE INDEX IF NOT EXISTS historical_identity_members_lookup_idx
  ON historical_identity_members (shop_domain, identity_type, value_hash);
CREATE INDEX IF NOT EXISTS historical_identity_members_customer_idx
  ON historical_identity_members (shop_domain, shopify_customer_id);

CREATE OR REPLACE VIEW historical_identity_claims AS
SELECT
  shop_domain,
  identity_type,
  value_hash,
  count(DISTINCT shopify_customer_id)::integer AS customer_count,
  CASE
    WHEN count(DISTINCT shopify_customer_id) = 1 THEN 'active'
    ELSE 'conflicted'
  END AS claim_state
FROM historical_identity_members
WHERE validity = 'valid'
GROUP BY shop_domain, identity_type, value_hash;

COMMIT;
