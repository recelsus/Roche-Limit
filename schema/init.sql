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
    key_plain TEXT,
    key_hash TEXT NOT NULL,
    key_prefix TEXT,
    service_name TEXT,
    access_level INTEGER NOT NULL CHECK (access_level >= 0),
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (key_hash, service_name)
);

CREATE INDEX IF NOT EXISTS idx_ip_rules_effect_enabled
    ON ip_rules (effect, enabled);

CREATE INDEX IF NOT EXISTS idx_ip_rules_value_prefix_enabled
    ON ip_rules (value_text, prefix_length, enabled);

CREATE INDEX IF NOT EXISTS idx_ip_service_levels_service_rule_enabled
    ON ip_service_levels (service_name, ip_rule_id, enabled);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash
    ON api_keys (key_hash);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash_service_enabled
    ON api_keys (key_hash, service_name, enabled);
