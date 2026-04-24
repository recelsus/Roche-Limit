CREATE TABLE IF NOT EXISTS login_failures (
    id INTEGER PRIMARY KEY,
    client_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_failed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_ip, username)
);

CREATE TABLE IF NOT EXISTS csrf_tokens (
    id INTEGER PRIMARY KEY,
    purpose TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    client_ip TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_failures_client_ip_username
    ON login_failures (client_ip, username);

CREATE INDEX IF NOT EXISTS idx_csrf_tokens_purpose_hash_expires_at
    ON csrf_tokens (purpose, token_hash, expires_at);
