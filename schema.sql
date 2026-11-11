-- Send log for the contact form's limits (see lib/guard.ts). Run once against the D1 database:
--   npx wrangler d1 execute glasgowshipyard --remote --file=schema.sql
-- Only SHA-256 hashes of the email and IP are stored, one row per message actually sent
-- (at most 15 a day), so no cleanup is needed.
CREATE TABLE IF NOT EXISTS gs_contact_log (email_hash TEXT NOT NULL, ip_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS gs_contact_log_email ON gs_contact_log (email_hash, created_at);
CREATE INDEX IF NOT EXISTS gs_contact_log_ip ON gs_contact_log (ip_hash, created_at);
CREATE INDEX IF NOT EXISTS gs_contact_log_created ON gs_contact_log (created_at);
