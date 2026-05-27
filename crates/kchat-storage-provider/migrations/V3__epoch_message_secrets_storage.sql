CREATE TABLE IF NOT EXISTS openmls_group_epoch_meta (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    migration_done INTEGER NOT NULL,
    PRIMARY KEY (provider_version, group_id)
);

CREATE TABLE IF NOT EXISTS openmls_group_epoch_message_secrets (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    message_secrets BLOB NOT NULL,
    PRIMARY KEY (provider_version, group_id, epoch)
);
