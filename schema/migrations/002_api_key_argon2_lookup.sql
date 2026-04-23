-- Move API key verification to Argon2id with a peppered lookup hash.
-- Existing SHA-256 API key rows cannot be converted without plaintext and are removed.
ALTER TABLE api_keys ADD COLUMN key_lookup_hash TEXT;
DELETE FROM api_keys;
CREATE INDEX IF NOT EXISTS idx_api_keys_key_lookup_hash
    ON api_keys (key_lookup_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key_lookup_hash_service
    ON api_keys (key_lookup_hash, service_name);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_lookup_hash_service_enabled
    ON api_keys (key_lookup_hash, service_name, enabled);
