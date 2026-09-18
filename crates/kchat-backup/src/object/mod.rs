mod envelope;
mod io;
mod writer;

pub use io::{BackupByteSink, BackupByteSource, copy_opaque_bytes_v1};
pub use writer::{BackupObjectDescriptor, BackupObjectWriterV1, seal_object_v1};
