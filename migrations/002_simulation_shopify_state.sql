BEGIN;

CREATE TABLE IF NOT EXISTS simulation_shopify_customers (
  customer_id text PRIMARY KEY,
  phone_e164 text,
  metafields jsonb NOT NULL DEFAULT '{}'::jsonb,
  tags text[] NOT NULL DEFAULT ARRAY[]::text[],
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMIT;
