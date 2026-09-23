BEGIN;

CREATE TABLE IF NOT EXISTS fiscal_registry_cache (
  cnpj_normalized CHAR(14) PRIMARY KEY,
  found BOOLEAN NOT NULL,
  active BOOLEAN NOT NULL,
  status TEXT NOT NULL,
  checked_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT fiscal_registry_cache_cnpj_format
    CHECK (cnpj_normalized ~ '^[0-9]{14}$')
);

CREATE INDEX IF NOT EXISTS fiscal_registry_cache_expires_at_idx
  ON fiscal_registry_cache (expires_at);

COMMIT;
