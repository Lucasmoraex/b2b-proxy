BEGIN;

-- Existing registrations and new requests without the optional field remain
-- legacy-compatible. The marker is true only when employee_range exists in the
-- encrypted operational payload. The value itself is never stored here.
ALTER TABLE registrations
  ADD COLUMN IF NOT EXISTS employee_range_required boolean NOT NULL DEFAULT false;

COMMIT;
