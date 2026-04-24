ALTER TABLE audit_events ADD COLUMN prev_event_hash TEXT;
ALTER TABLE audit_events ADD COLUMN event_hash TEXT;
UPDATE audit_events
SET event_hash = printf('legacy-%d', id)
WHERE event_hash IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_event_hash
    ON audit_events (event_hash);
CREATE INDEX IF NOT EXISTS idx_audit_events_prev_event_hash
    ON audit_events (prev_event_hash);
