use kchat_backup::{BackupByteSink, BackupByteSource, MAX_IO_CHUNK_BYTES_V1, copy_opaque_bytes_v1};

struct Source {
    bytes: Vec<u8>,
    offset: usize,
    largest_request: usize,
}

impl BackupByteSource for Source {
    fn read_chunk(&mut self, destination: &mut [u8]) -> Result<usize, kchat_backup::BackupError> {
        self.largest_request = self.largest_request.max(destination.len());
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(destination.len());
        destination[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        Ok(count)
    }
}

#[derive(Default)]
struct Sink(Vec<u8>);

impl BackupByteSink for Sink {
    fn write_chunk(&mut self, source: &[u8]) -> Result<(), kchat_backup::BackupError> {
        self.0.extend_from_slice(source);
        Ok(())
    }
}

#[test]
fn copies_opaque_non_text_bytes_without_interpreting_them() {
    let bytes = vec![0xff, 0x00, 0xc0, 0x80, 0x1a, 0x5b, 0x7b, 0x00];
    let mut source = Source {
        bytes: bytes.clone(),
        offset: 0,
        largest_request: 0,
    };
    let mut sink = Sink::default();

    assert_eq!(
        copy_opaque_bytes_v1(&mut source, &mut sink).unwrap(),
        bytes.len() as u64
    );
    assert_eq!(sink.0, bytes);
    assert!(source.largest_request <= MAX_IO_CHUNK_BYTES_V1);
}
