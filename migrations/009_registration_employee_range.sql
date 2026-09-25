BEGIN;

-- Existing registrations are legacy-compatible: only registrations created by
-- the v2 contract after this migration require employee_range in their
-- encrypted operational payload. The value itself is never stored here.
ALTER TABLE registrations
  ADD COLUMN IF NOT EXISTS employee_range_required boolean NOT NULL DEFAULT false;

COMMIT;
