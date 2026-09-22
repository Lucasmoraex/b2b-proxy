BEGIN;

CREATE TABLE IF NOT EXISTS registrations (
  id uuid PRIMARY KEY,
  email_normalized text NOT NULL,
  cnpj_normalized char(14) NOT NULL,
  phone_e164 text NOT NULL,
  shopify_customer_id text,
  status text NOT NULL CHECK (status IN (
    'reserved', 'pending_shopify', 'pending_validation', 'pending_review',
    'approved', 'rejected', 'failed', 'expired'
  )),
  idempotency_key uuid NOT NULL,
  request_digest char(64) NOT NULL,
  fiscal_status text NOT NULL,
  fiscal_validated_at timestamptz NOT NULL,
  sync_completed_at timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT registrations_email_unique UNIQUE (email_normalized),
  CONSTRAINT registrations_cnpj_unique UNIQUE (cnpj_normalized),
  CONSTRAINT registrations_phone_unique UNIQUE (phone_e164),
  CONSTRAINT registrations_shopify_customer_unique UNIQUE (shopify_customer_id),
  CONSTRAINT registrations_idempotency_unique UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS registrations_status_idx ON registrations (status);
CREATE INDEX IF NOT EXISTS registrations_expires_idx ON registrations (expires_at);

CREATE TABLE IF NOT EXISTS webhook_events (
  event_id text PRIMARY KEY,
  topic text NOT NULL,
  payload_digest char(64) NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS outbox (
  id uuid PRIMARY KEY,
  registration_id uuid NOT NULL REFERENCES registrations(id) ON DELETE CASCADE,
  operation text NOT NULL CHECK (operation IN (
    'sync_registration', 'approve_registration', 'reject_registration', 'reconcile_registration'
  )),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  last_error text,
  locked_at timestamptz,
  locked_by text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS outbox_pending_operation_unique
  ON outbox (registration_id, operation) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS outbox_ready_idx
  ON outbox (next_attempt_at) WHERE processed_at IS NULL;

COMMIT;
