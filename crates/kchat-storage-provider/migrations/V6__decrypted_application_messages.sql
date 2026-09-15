CREATE TABLE IF NOT EXISTS openmls_decrypted_application_messages (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    message_id TEXT NOT NULL,
    ciphertext_digest BLOB NOT NULL,
    plaintext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, message_id)
);

CREATE INDEX IF NOT EXISTS openmls_decrypted_application_messages_expires_at_idx
ON openmls_decrypted_application_messages (expires_at);
