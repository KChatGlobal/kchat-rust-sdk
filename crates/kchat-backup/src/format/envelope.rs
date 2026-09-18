pub(crate) const ENVELOPE_MAGIC: &[u8; 4] = b"KCBK";
pub(crate) const ENVELOPE_VERSION: u16 = 1;
pub(crate) const CRYPTO_SUITE_ID: u16 = 1;
pub(crate) const COMPRESSION_ID: u16 = 1;
pub(crate) const ENVELOPE_HEADER_BYTES: usize = 29;
pub(crate) const STREAM_NONCE_PREFIX_BYTES: usize = 19;
pub(crate) const COMPRESSED_BLOCK_BYTES: usize = 64 * 1024;
pub(crate) const AEAD_TAG_BYTES: usize = 16;

pub(crate) fn serialize_header(
    nonce_prefix: &[u8; STREAM_NONCE_PREFIX_BYTES],
) -> [u8; ENVELOPE_HEADER_BYTES] {
    let mut header = [0_u8; ENVELOPE_HEADER_BYTES];
    header[..4].copy_from_slice(ENVELOPE_MAGIC);
    header[4..6].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&CRYPTO_SUITE_ID.to_be_bytes());
    header[8..10].copy_from_slice(&COMPRESSION_ID.to_be_bytes());
    header[10..].copy_from_slice(nonce_prefix);
    header
}
