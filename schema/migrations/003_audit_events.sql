CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    target_type TEXT,
    target_id TEXT,
    service_name TEXT,
    access_level INTEGER,
    client_ip TEXT,
    request_id TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events (created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_type_created_at
    ON audit_events (event_type, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_request_id
    ON audit_events (request_id);
