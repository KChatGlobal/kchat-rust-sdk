use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, DeserializeOwned, Visitor},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::FileCryptoError;

/// Decodes exactly one CBOR item spanning all of `payload`.
///
/// The zeroized scratch buffer is as large as the payload, so `ciborium` reads every
/// definite-length byte string into it instead of a growing `Vec` that would leave key copies.
pub(crate) fn decode_cbor<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FileCryptoError> {
    let mut reader = payload;
    let mut scratch = Zeroizing::new(vec![0_u8; payload.len()]);
    let value = ciborium::de::from_reader_with_buffer(&mut reader, &mut scratch[..])
        .map_err(|_| FileCryptoError::malformed_message())?;
    if !reader.is_empty() {
        return Err(FileCryptoError::malformed_message());
    }
    Ok(value)
}

/// CBOR byte string of exactly `N` bytes, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct FixedBytes<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(FixedBytesVisitor::<N>)
    }
}

struct FixedBytesVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for FixedBytesVisitor<N> {
    type Value = FixedBytes<N>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "byte string of {N} bytes")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        let array = bytes
            .try_into()
            .map_err(|_| E::invalid_length(bytes.len(), &self))?;
        Ok(FixedBytes(array))
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&Zeroizing::new(bytes))
    }
}

/// Variable-length CBOR byte string, zeroized on drop. Bounded by the payload size check done
/// before decoding.
pub(crate) struct ByteString(pub(crate) Zeroizing<Vec<u8>>);

impl Serialize for ByteString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ByteString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(ByteStringVisitor)
    }
}

struct ByteStringVisitor;

impl<'de> Visitor<'de> for ByteStringVisitor {
    type Value = ByteString;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("byte string")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        Ok(ByteString(Zeroizing::new(bytes.to_vec())))
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
        Ok(ByteString(Zeroizing::new(bytes)))
    }
}
