CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_rules (
    id INTEGER PRIMARY KEY,
    value_text TEXT NOT NULL,
    address_family TEXT NOT NULL CHECK (address_family IN ('ipv4', 'ipv6')),
    rule_type TEXT NOT NULL CHECK (rule_type IN ('single', 'cidr')),
    prefix_length INTEGER,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_service_levels (
    id INTEGER PRIMARY KEY,
    ip_rule_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    access_level INTEGER NOT NULL CHECK (access_level >= 0),
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ip_rule_id) REFERENCES ip_rules(id),
    UNIQUE (ip_rule_id, service_name)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    key_hash TEXT NOT NULL,
    key_lookup_hash TEXT NOT NULL,
    key_prefix TEXT,
    service_name TEXT,
    access_level INTEGER NOT NULL CHECK (access_level >= 0),
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (key_lookup_hash, service_name)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_credentials (
    user_id INTEGER PRIMARY KEY,
    password_hash TEXT NOT NULL,
    password_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_service_levels (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    access_level INTEGER NOT NULL CHECK (access_level >= 0),
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, service_name)
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY,
    session_token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

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

CREATE INDEX IF NOT EXISTS idx_ip_rules_effect_enabled
    ON ip_rules (effect, enabled);

CREATE INDEX IF NOT EXISTS idx_ip_rules_value_prefix_enabled
    ON ip_rules (value_text, prefix_length, enabled);

CREATE INDEX IF NOT EXISTS idx_ip_service_levels_service_rule_enabled
    ON ip_service_levels (service_name, ip_rule_id, enabled);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_lookup_hash
    ON api_keys (key_lookup_hash);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_lookup_hash_service_enabled
    ON api_keys (key_lookup_hash, service_name, enabled);

CREATE INDEX IF NOT EXISTS idx_users_username_enabled
    ON users (username, enabled);

CREATE INDEX IF NOT EXISTS idx_user_service_levels_user_service_enabled
    ON user_service_levels (user_id, service_name, enabled);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash
    ON user_sessions (session_token_hash);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
    ON user_sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events (created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_type_created_at
    ON audit_events (event_type, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_request_id
    ON audit_events (request_id);
