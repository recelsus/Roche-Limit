CREATE TABLE IF NOT EXISTS client_certs (
    id INTEGER PRIMARY KEY,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    serial_number TEXT,
    subject_dn TEXT,
    issuer_dn TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    not_before TEXT,
    not_after TEXT,
    last_used_at TEXT,
    last_used_ip TEXT,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS client_cert_service_levels (
    id INTEGER PRIMARY KEY,
    client_cert_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    access_level INTEGER NOT NULL CHECK (access_level >= 0),
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_cert_id) REFERENCES client_certs(id),
    UNIQUE (client_cert_id, service_name)
);

CREATE INDEX IF NOT EXISTS idx_client_certs_fingerprint_enabled
    ON client_certs (fingerprint_sha256, enabled);

CREATE INDEX IF NOT EXISTS idx_client_certs_last_used_at
    ON client_certs (last_used_at);

CREATE INDEX IF NOT EXISTS idx_client_cert_service_levels_service_cert_enabled
    ON client_cert_service_levels (service_name, client_cert_id, enabled);
