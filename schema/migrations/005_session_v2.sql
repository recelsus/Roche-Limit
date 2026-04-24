CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY,
    session_token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash
    ON user_sessions (session_token_hash);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
    ON user_sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_user_sessions_absolute_expires_at
    ON user_sessions (absolute_expires_at);

CREATE INDEX IF NOT EXISTS idx_user_sessions_idle_expires_at
    ON user_sessions (idle_expires_at);
