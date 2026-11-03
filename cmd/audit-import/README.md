# Offline SQLite 12 → PostgreSQL import

This opt-in command is separate from proxy startup. It does not upgrade SQLite,
recover interrupted audits, delete old files, change deployment configuration,
or re-encrypt historical evidence. Only the released schema-12 migration set is
accepted. Older SQLite databases must be upgraded using the old application
before this migration, with a backup.

1. Stop the old SQLite proxy and the target PostgreSQL proxy. Take and verify a
   backup of the SQLite database **together with any `-wal` and `-shm` files**, the
   existing raw 32-byte audit key, and the old configuration. Do not copy only the
   database file while WAL exists. Keep backup secrets outside the repository.
2. Provision an empty PostgreSQL database/schema. An already initialized empty
   application schema is supported. Existing audit data, custom rules, derived
   objects, or a prior completed import are rejected. Only the exact built-in
   user-agent rule may be present and is replaced by the source rule set.
3. Build `go build -o audit-import ./cmd/audit-import`. Supply the destination
   connection string via `AUDIT_IMPORT_DATABASE_URL` using your secret-management
   mechanism, not a command-line argument or shell-history literal.
4. Run a complete trial:
   `./audit-import --source /backup/audit.db --key-file /backup/audit.key --service-stopped --dry-run`
5. After reviewing the table-count JSON report, run the same command without
   `--dry-run`. A failure prints a stable error code, never driver errors,
   connection strings, ciphertext, keys or plaintext. Keep services stopped
   throughout; the flag is an operator confirmation, not process discovery.
6. Only after successful import, point the PostgreSQL application at the new
   database and the **same** existing audit key. Validate representative evidence
   queries before reopening traffic. Retain the old backup until your migration
   acceptance and retention requirements are satisfied.

The source is opened read-only with one consistent transaction, including its
WAL. No checkpoint, upgrade, recovery or journal-mode change is requested.
Database and WAL bytes are preserved; SQLite can update transient SHM reader-lock
metadata when opening a normal WAL snapshot, so SHM byte identity is not promised.
The key file is read only and is never generated or replaced.

The target uses the runtime writer advisory lock and a single transaction for
schema initialization, copying, validation and sequence restoration. Dry-run
rolls back all of these, including schema and sequence changes. Validations cover
foreign keys, exact typed row digests/counts, authenticated encrypted fields,
content/binary identity, graph reconstruction hashes, and the full integrity MAC
chain including events retained after audit deletion. Unsupported NUL or invalid
UTF-8 in source TEXT fails rather than being cleaned. Identity sequences preserve
SQLite allocation high-water marks, including deleted highest IDs. PostgreSQL
receives ciphertext bytes unchanged and no history is re-signed.

Rollback before new PostgreSQL writes means stopping the new service and restoring
the saved SQLite deployment and original key/configuration with the old release.
**New PostgreSQL writes are not copied back to SQLite.** Returning to the old
backup after accepting new traffic would lose those new records; plan cutover and
rollback accordingly. Never run both services against the same traffic during
cutover. No production dataset is needed for importer tests.

Integration tests require `DATABASE_URL` pointing at a disposable PostgreSQL test
database where the test role can create/drop schemas. They use only synthetic
fixtures: `go test ./internal/storage/migrate`.

If `target_commit_outcome_unknown` is reported after a connection interruption,
do not assume rollback and do not start a blind retry. Reconnect and inspect the
`offline_import_history` marker and imported table counts before deciding whether
to resume cutover or retry. PostgreSQL commits all import rows together, but a
client can lose the commit acknowledgment.
