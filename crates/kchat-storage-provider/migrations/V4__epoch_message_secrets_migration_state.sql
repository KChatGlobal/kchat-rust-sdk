CREATE TABLE IF NOT EXISTS openmls_epoch_migration_state (
    provider_version INTEGER NOT NULL PRIMARY KEY,
    legacy_message_secrets_migration_done INTEGER NOT NULL
);
