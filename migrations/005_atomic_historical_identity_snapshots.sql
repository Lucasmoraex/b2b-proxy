BEGIN;

ALTER TABLE historical_identity_import_runs
  DROP CONSTRAINT IF EXISTS historical_identity_import_runs_status_check;
ALTER TABLE historical_identity_import_runs
  ADD CONSTRAINT historical_identity_import_runs_status_check
  CHECK (status IN ('running', 'staging', 'completed', 'failed'));

-- Synthetic .invalid domains are accepted by the schema for isolated local
-- simulation. Runtime guards still forbid them outside simulation mode.
ALTER TABLE historical_identity_index_metadata
  DROP CONSTRAINT historical_identity_metadata_shop_domain;
ALTER TABLE historical_identity_index_metadata
  ADD CONSTRAINT historical_identity_metadata_shop_domain CHECK (
    shop_domain ~ '^[a-z0-9][a-z0-9-]*\.myshopify\.com$'
    OR shop_domain ~ '^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*\.invalid$'
  );

ALTER TABLE historical_identity_import_runs
  DROP CONSTRAINT historical_identity_runs_shop_domain;
ALTER TABLE historical_identity_import_runs
  ADD CONSTRAINT historical_identity_runs_shop_domain CHECK (
    shop_domain ~ '^[a-z0-9][a-z0-9-]*\.myshopify\.com$'
    OR shop_domain ~ '^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*\.invalid$'
  );

ALTER TABLE historical_identity_import_runs
  ADD CONSTRAINT historical_identity_runs_shop_id_unique UNIQUE (shop_domain, id);

ALTER TABLE historical_identity_index_metadata
  ADD COLUMN active_import_run_id uuid;

ALTER TABLE historical_identity_index_metadata
  ADD CONSTRAINT historical_identity_metadata_active_run_fk
  FOREIGN KEY (shop_domain, active_import_run_id)
  REFERENCES historical_identity_import_runs (shop_domain, id);

CREATE TABLE historical_customer_identity_snapshot_states (
  import_run_id uuid NOT NULL,
  shop_domain text NOT NULL,
  shopify_customer_id text NOT NULL,
  identity_type text NOT NULL CHECK (identity_type IN ('email', 'cnpj', 'phone')),
  validity text NOT NULL CHECK (validity IN ('valid', 'invalid', 'incomplete')),
  sources text[] NOT NULL DEFAULT ARRAY[]::text[],
  imported_at timestamptz NOT NULL,
  PRIMARY KEY (import_run_id, shop_domain, shopify_customer_id, identity_type),
  CONSTRAINT historical_snapshot_states_run_fk
    FOREIGN KEY (shop_domain, import_run_id)
    REFERENCES historical_identity_import_runs (shop_domain, id),
  CONSTRAINT historical_snapshot_states_customer_id_nonempty
    CHECK (length(shopify_customer_id) BETWEEN 1 AND 256)
);

CREATE INDEX historical_snapshot_states_shop_run_idx
  ON historical_customer_identity_snapshot_states (shop_domain, import_run_id);

CREATE TABLE historical_identity_snapshot_members (
  import_run_id uuid NOT NULL,
  shop_domain text NOT NULL,
  shopify_customer_id text NOT NULL,
  identity_type text NOT NULL CHECK (identity_type IN ('email', 'cnpj', 'phone')),
  value_hash char(64) NOT NULL,
  validity text NOT NULL DEFAULT 'valid' CHECK (validity = 'valid'),
  sources text[] NOT NULL DEFAULT ARRAY[]::text[],
  imported_at timestamptz NOT NULL,
  PRIMARY KEY (import_run_id, shop_domain, shopify_customer_id, identity_type, value_hash),
  CONSTRAINT historical_snapshot_members_run_fk
    FOREIGN KEY (shop_domain, import_run_id)
    REFERENCES historical_identity_import_runs (shop_domain, id),
  CONSTRAINT historical_snapshot_members_hash_format
    CHECK (value_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT historical_snapshot_members_customer_id_nonempty
    CHECK (length(shopify_customer_id) BETWEEN 1 AND 256)
);

CREATE INDEX historical_snapshot_members_lookup_idx
  ON historical_identity_snapshot_members (shop_domain, import_run_id, identity_type, value_hash);
CREATE INDEX historical_snapshot_members_customer_idx
  ON historical_identity_snapshot_members (shop_domain, import_run_id, shopify_customer_id);

CREATE OR REPLACE VIEW historical_identity_claims AS
SELECT
  member.shop_domain,
  member.identity_type,
  member.value_hash,
  count(DISTINCT member.shopify_customer_id)::integer AS customer_count,
  CASE
    WHEN count(DISTINCT member.shopify_customer_id) = 1 THEN 'active'
    ELSE 'conflicted'
  END AS claim_state
FROM historical_identity_snapshot_members member
JOIN historical_identity_index_metadata metadata
  ON metadata.shop_domain = member.shop_domain
  AND metadata.active_import_run_id = member.import_run_id
JOIN historical_identity_import_runs import_run
  ON import_run.id = metadata.active_import_run_id
  AND import_run.shop_domain = metadata.shop_domain
  AND import_run.status = 'completed'
WHERE member.validity = 'valid'
GROUP BY member.shop_domain, member.identity_type, member.value_hash;

COMMIT;
