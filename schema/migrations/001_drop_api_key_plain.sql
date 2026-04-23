-- Remove plaintext API key storage from databases created by earlier versions.
ALTER TABLE api_keys DROP COLUMN key_plain;
