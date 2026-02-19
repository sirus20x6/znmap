-- pg_schema.sql — nmap_live schema migration
-- Apply with: psql postgresql:///security < pg_schema.sql

BEGIN;

-- Live progress tracking columns on runs
ALTER TABLE nmap_live.runs ADD COLUMN IF NOT EXISTS hosts_done INT DEFAULT 0;
ALTER TABLE nmap_live.runs ADD COLUMN IF NOT EXISTS hosts_total INT DEFAULT 0;

COMMIT;
