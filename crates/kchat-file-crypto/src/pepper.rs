use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::FileCryptoError;

const PEPPER_COMMITMENT_LABEL: &[u8] = b"kchat-storage/pepper-commit/v1";
pub(crate) const PEPPER_BYTES: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Pepper {
    #[zeroize(skip)]
    generation: u64,
    bytes: [u8; PEPPER_BYTES],
}

impl Pepper {
    pub(crate) fn generate(generation: u64) -> Result<Self, FileCryptoError> {
        let mut bytes = [0_u8; PEPPER_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| FileCryptoError::io_error())?;
        Ok(Self { generation, bytes })
    }

    pub(crate) fn from_bytes(generation: u64, bytes: &[u8]) -> Result<Self, FileCryptoError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| FileCryptoError::invalid_argument())?;
        Ok(Self { generation, bytes })
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; PEPPER_BYTES] {
        &self.bytes
    }

    /// `SHA-256(label || pepper)`: public, used for the server CAS and to check a received pepper.
    pub(crate) fn commitment(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(PEPPER_COMMITMENT_LABEL)
            .chain_update(self.bytes)
            .finalize()
            .into()
    }
}

impl core::fmt::Debug for Pepper {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Pepper")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
