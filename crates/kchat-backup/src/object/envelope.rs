//! V1 encrypted-object wire format. All integer fields are big-endian.
//!
//! ObjectEnvelopeV1 (fixed header: 29 bytes)
//!   0..4    magic: "KCBK"
//!   4..6    format_version: u16 = 1
//!   6..8    crypto_suite_id: u16 = 1  (XChaCha20Poly1305 STREAM-BE32)
//!   8..10   compression_id: u16 = 1   (Zstd level 3, no dictionary)
//!   10..29  stream_nonce_prefix: [u8; 19]
//!   EncryptedStreamBlockV1 (repeated until EOF; at least one block)
//!     ciphertext_len: u32
//!     ciphertext: [u8; ciphertext_len]

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
