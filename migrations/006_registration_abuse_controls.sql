BEGIN;

ALTER TABLE registrations
  ADD COLUMN IF NOT EXISTS request_ip_hash char(64);

ALTER TABLE registrations
  DROP CONSTRAINT IF EXISTS registrations_request_ip_hash_format;
ALTER TABLE registrations
  ADD CONSTRAINT registrations_request_ip_hash_format
  CHECK (request_ip_hash IS NULL OR request_ip_hash ~ '^[0-9a-f]{64}$');

CREATE INDEX IF NOT EXISTS registrations_active_ip_hash_idx
  ON registrations (request_ip_hash, expires_at)
  WHERE request_ip_hash IS NOT NULL
    AND shopify_customer_id IS NULL
    AND status IN ('reserved', 'pending_shopify', 'pending_validation', 'pending_review');

CREATE TABLE IF NOT EXISTS registration_rate_limit_buckets (
  scope text NOT NULL CHECK (scope IN (
    'registration_ip',
    'registration_identity_email',
    'registration_identity_cnpj',
    'registration_identity_phone'
  )),
  key_hash char(64) NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz NOT NULL,
  hit_count integer NOT NULL CHECK (hit_count > 0),
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (scope, key_hash, window_started_at)
);

CREATE INDEX IF NOT EXISTS registration_rate_limit_buckets_expires_idx
  ON registration_rate_limit_buckets (expires_at);

CREATE TABLE IF NOT EXISTS registration_request_admissions (
  idempotency_key uuid PRIMARY KEY,
  request_key_digest char(64) NOT NULL CHECK (request_key_digest ~ '^[0-9a-f]{64}$'),
  ip_key_hash char(64) NOT NULL CHECK (ip_key_hash ~ '^[0-9a-f]{64}$'),
  admitted_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS registration_request_admissions_expires_idx
  ON registration_request_admissions (expires_at);

COMMIT;
