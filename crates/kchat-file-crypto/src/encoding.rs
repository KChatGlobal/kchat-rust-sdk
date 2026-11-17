//! Injective encoding for AAD, HKDF `info` and signed messages: `lp(label) || field...`, where
//! `lp(b) = u32-be(len(b)) || b` and integers are fixed-width big-endian.

pub(crate) struct Encoder(Vec<u8>);

impl Encoder {
    pub(crate) fn new(label: &str) -> Self {
        Self(Vec::with_capacity(128)).text(label)
    }

    pub(crate) fn bytes(mut self, value: &[u8]) -> Self {
        // Every field is far below 4 GiB, so the fallback is unreachable.
        let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(value);
        self
    }

    pub(crate) fn text(self, value: &str) -> Self {
        self.bytes(value.as_bytes())
    }

    pub(crate) fn u64(mut self, value: u64) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(crate) fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}
