BEGIN;

ALTER TABLE registrations
  ALTER COLUMN email_normalized DROP NOT NULL,
  ALTER COLUMN cnpj_normalized DROP NOT NULL,
  ALTER COLUMN phone_e164 DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS retention_hold_until timestamptz;

CREATE INDEX IF NOT EXISTS registrations_retention_hold_idx
  ON registrations (retention_hold_until)
  WHERE retention_hold_until IS NOT NULL;

CREATE TABLE IF NOT EXISTS registration_identity_claims (
  registration_id uuid NOT NULL REFERENCES registrations(id) ON DELETE CASCADE,
  identity_type text NOT NULL CHECK (identity_type IN ('email', 'cnpj', 'phone')),
  key_version text NOT NULL CHECK (key_version ~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$'),
  value_hash char(64) NOT NULL CHECK (value_hash ~ '^[0-9a-f]{64}$'),
  claim_state text NOT NULL CHECK (claim_state IN ('reserved', 'active', 'tombstoned', 'released')),
  created_at timestamptz NOT NULL,
  activated_at timestamptz,
  released_at timestamptz,
  PRIMARY KEY (registration_id, identity_type, key_version),
  CONSTRAINT registration_identity_claim_lifecycle CHECK (
    (claim_state = 'reserved' AND activated_at IS NULL AND released_at IS NULL)
    OR (claim_state IN ('active', 'tombstoned') AND activated_at IS NOT NULL AND released_at IS NULL)
    OR (claim_state = 'released' AND released_at IS NOT NULL)
  )
);

-- This is the final atomic uniqueness guarantee. Released claims remain as
-- lifecycle evidence but no longer block a new registration.
CREATE UNIQUE INDEX IF NOT EXISTS registration_identity_claims_blocking_unique
  ON registration_identity_claims (identity_type, key_version, value_hash)
  WHERE claim_state <> 'released';

CREATE INDEX IF NOT EXISTS registration_identity_claims_registration_idx
  ON registration_identity_claims (registration_id, claim_state);
CREATE INDEX IF NOT EXISTS registration_identity_claims_lookup_idx
  ON registration_identity_claims (identity_type, key_version, value_hash, claim_state);

-- Keeps future historical snapshot refreshes race-safe after plaintext
-- registration columns become NULL. The original historical blind index is
-- unchanged; this is an auxiliary HMAC in the new-registration key domain.
ALTER TABLE historical_identity_snapshot_members
  ADD COLUMN IF NOT EXISTS registration_key_version text,
  ADD COLUMN IF NOT EXISTS registration_value_hash char(64);
ALTER TABLE historical_identity_snapshot_members
  ADD CONSTRAINT historical_snapshot_registration_hash_pair CHECK (
    (registration_key_version IS NULL AND registration_value_hash IS NULL)
    OR (
      registration_key_version ~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$'
      AND registration_value_hash ~ '^[0-9a-f]{64}$'
    )
  );
CREATE INDEX IF NOT EXISTS historical_snapshot_registration_claim_lookup_idx
  ON historical_identity_snapshot_members (
    shop_domain, import_run_id, identity_type, registration_key_version, registration_value_hash
  ) WHERE registration_value_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS registration_operational_payloads (
  registration_id uuid PRIMARY KEY REFERENCES registrations(id) ON DELETE CASCADE,
  ciphertext bytea,
  nonce bytea,
  auth_tag bytea,
  encryption_key_version text NOT NULL
    CHECK (encryption_key_version ~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$'),
  needed_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  purged_at timestamptz,
  CONSTRAINT registration_operational_payload_cipher_state CHECK (
    (purged_at IS NULL
      AND ciphertext IS NOT NULL
      AND octet_length(nonce) = 12
      AND octet_length(auth_tag) = 16)
    OR (purged_at IS NOT NULL
      AND ciphertext IS NULL
      AND nonce IS NULL
      AND auth_tag IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS registration_operational_payloads_retention_idx
  ON registration_operational_payloads (needed_until)
  WHERE purged_at IS NULL;

CREATE INDEX IF NOT EXISTS outbox_processed_retention_idx
  ON outbox (processed_at)
  WHERE processed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS webhook_events_processed_retention_idx
  ON webhook_events (processed_at);
CREATE INDEX IF NOT EXISTS historical_import_runs_retention_idx
  ON historical_identity_import_runs (status, completed_at)
  WHERE status IN ('failed', 'completed');

COMMIT;
