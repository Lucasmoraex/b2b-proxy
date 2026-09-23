BEGIN;

ALTER TABLE registrations
  ADD COLUMN IF NOT EXISTS request_digest_version text;
ALTER TABLE registrations
  ADD CONSTRAINT registrations_request_digest_version_check
  CHECK (request_digest_version IS NULL OR request_digest_version = 'hmac-sha256-v1');

ALTER TABLE webhook_events
  ADD COLUMN IF NOT EXISTS payload_digest_version text;
ALTER TABLE webhook_events
  ADD CONSTRAINT webhook_events_payload_digest_version_check
  CHECK (payload_digest_version IS NULL OR payload_digest_version = 'hmac-sha256-v1');

ALTER TABLE registration_request_admissions
  ADD COLUMN IF NOT EXISTS request_key_digest_version text;
ALTER TABLE registration_request_admissions
  ADD CONSTRAINT registration_admissions_digest_version_check
  CHECK (request_key_digest_version IS NULL OR request_key_digest_version = 'hmac-sha256-v1');

ALTER TABLE outbox
  ADD COLUMN IF NOT EXISTS error_code text,
  ADD COLUMN IF NOT EXISTS error_category text,
  ADD COLUMN IF NOT EXISTS upstream_status integer,
  ADD COLUMN IF NOT EXISTS error_recorded_at timestamptz;
ALTER TABLE outbox
  ADD CONSTRAINT outbox_error_code_format
  CHECK (error_code IS NULL OR error_code ~ '^[a-z][a-z0-9_]{0,79}$'),
  ADD CONSTRAINT outbox_error_category_check
  CHECK (error_category IS NULL OR error_category IN (
    'conflict', 'historical_identity', 'internal', 'registry', 'shopify', 'validation'
  )),
  ADD CONSTRAINT outbox_upstream_status_check
  CHECK (upstream_status IS NULL OR upstream_status BETWEEN 100 AND 599);

ALTER TABLE historical_identity_import_runs
  ADD COLUMN IF NOT EXISTS error_code text,
  ADD COLUMN IF NOT EXISTS error_category text,
  ADD COLUMN IF NOT EXISTS upstream_status integer,
  ADD COLUMN IF NOT EXISTS error_recorded_at timestamptz;
ALTER TABLE historical_identity_import_runs
  ADD CONSTRAINT historical_import_error_code_format
  CHECK (error_code IS NULL OR error_code ~ '^[a-z][a-z0-9_]{0,79}$'),
  ADD CONSTRAINT historical_import_error_category_check
  CHECK (error_category IS NULL OR error_category IN (
    'conflict', 'historical_identity', 'internal', 'registry', 'shopify', 'validation'
  )),
  ADD CONSTRAINT historical_import_upstream_status_check
  CHECK (upstream_status IS NULL OR upstream_status BETWEEN 100 AND 599);

COMMIT;
