ALTER TABLE api_keys ADD COLUMN last_used_at TEXT;
ALTER TABLE api_keys ADD COLUMN last_used_ip TEXT;
ALTER TABLE api_keys ADD COLUMN last_failed_at TEXT;
ALTER TABLE api_keys ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key_prefix_unique
    ON api_keys (key_prefix)
    WHERE key_prefix IS NOT NULL;
