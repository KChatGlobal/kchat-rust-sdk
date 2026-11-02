mod error;
mod key;
mod reader;
mod writer;

pub use error::BackupFfiError;
pub use key::{
    BackupDescriptorBootstrap, BackupDescriptorHeader, BackupKeyMode, BackupMasterKey,
    BackupObjectContext, GeneratedMnemonicBackupKey, GeneratedPasswordBackupKey,
    OpenedBackupDescriptor, generate_mnemonic, generate_password, import_from_mnemonic,
    import_from_password, import_from_raw, parse_descriptor_header,
};
pub use reader::{BackupCiphertextSource, BackupPlaintextSink, open_backup_object_v1};
pub use writer::{
    BackupCiphertextSink, BackupObjectMetadata, BackupPlaintextSource, seal_backup_object_v1,
};
