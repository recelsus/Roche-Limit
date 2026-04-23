# DB Migration

`schema/init.sql` is the canonical schema for new databases.

Existing databases are upgraded by applying numbered SQL files from
`schema/migrations` in ascending order. The current applied version is stored in
`schema_metadata` under `migration_version`.

Rules:

- Migration files are forward-only.
- Downgrade is not supported.
- `init.sql` should represent the latest full schema.
- Each migration must be safe to run exactly once.
- Destructive changes must be explicit in a migration file.

Current migrations:

- `001_drop_api_key_plain.sql`
  Removes plaintext API key storage from databases created before plaintext
  storage was removed.
