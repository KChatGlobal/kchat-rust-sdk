//! Storage-independent encrypted backup primitives.

mod account;
mod context;
mod descriptor;
mod error;
mod key;
mod limits;
mod object;

pub use account::BackupAccountId;
pub use context::{
    BACKUP_FORMAT_VERSION_V1, BackupChunkId, BackupNamespaceId, BackupObjectContextV1,
};
pub use descriptor::{open_descriptor_v1, seal_descriptor_v1};
pub use error::{BackupError, BackupErrorCode};
pub use key::{BackupKeyMaterial, MnemonicBackupKey, PasswordBackupKey};
pub use limits::{
    MAX_CIPHERTEXT_OBJECT_BYTES_V1, MAX_COMPRESSED_OBJECT_BYTES_V1,
    MAX_ENCRYPTED_BLOCKS_PER_OBJECT_V1, MAX_IO_CHUNK_BYTES_V1, MAX_PLAINTEXT_OBJECT_BYTES_V1,
    MAX_ZSTD_WINDOW_BYTES_V1,
};
pub use object::{
    BackupByteSink, BackupByteSource, BackupObjectDescriptor, BackupObjectWriterV1,
    copy_opaque_bytes_v1, seal_object_v1,
};
