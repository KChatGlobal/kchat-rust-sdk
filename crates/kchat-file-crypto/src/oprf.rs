//! RFC 9497 VOPRF client (mode 0x01, ristretto255-SHA512).
//!
//! `voprf` types stay inside this module: they are `Clone` and expose the blind through `Debug`
//! and serialization.

use rand_core::{CryptoRng, RngCore};
use voprf::{EvaluationElement, Proof, Ristretto255, VoprfClient};
use zeroize::{Zeroize, Zeroizing};

use crate::{FileCryptoError, kkey::KKeyElement};

pub(crate) const ELEMENT_BYTES: usize = 32;
pub(crate) const OUTPUT_BYTES: usize = 64;
const PROOF_BYTES: usize = 64;

/// Blind states of one single-use batch, in request order.
pub(crate) struct BlindBatch(Vec<VoprfClient<Ristretto255>>);

impl BlindBatch {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Blinds `input` with a fresh blind, so repeated uploads of one content are unlinkable.
    pub(crate) fn blind(&mut self, input: &[u8]) -> Result<[u8; ELEMENT_BYTES], FileCryptoError> {
        let mut rng = SystemRng::default();
        // Fails only for empty or oversized inputs; ours are 32-byte hashes.
        let result = VoprfClient::<Ristretto255>::blind(input, &mut rng)
            .map_err(|_| FileCryptoError::invalid_argument())?;
        // A blind built from filler bytes would be predictable.
        if rng.failed {
            return Err(FileCryptoError::io_error());
        }
        self.0.push(result.state);
        Ok(result.message.serialize().into())
    }

    /// Verifies the batch proof, then unblinds each element. `inputs` are the blinded inputs in
    /// order; one bad element rejects the whole batch.
    pub(crate) fn finalize(
        &self,
        inputs: Vec<&[u8]>,
        evaluated_elements: &[Vec<u8>],
        proof: &[u8],
        public_key: KKeyElement,
    ) -> Result<Vec<Zeroizing<[u8; OUTPUT_BYTES]>>, FileCryptoError> {
        let invalid = FileCryptoError::kkey_proof_invalid;
        // `voprf` ignores trailing bytes, so exact lengths are checked here.
        if inputs.len() != self.0.len()
            || evaluated_elements.len() != self.0.len()
            || proof.len() != PROOF_BYTES
        {
            return Err(invalid());
        }
        let proof = Proof::<Ristretto255>::deserialize(proof).map_err(|_| invalid())?;
        let messages = evaluated_elements
            .iter()
            .map(|element| {
                if element.len() != ELEMENT_BYTES {
                    return Err(invalid());
                }
                EvaluationElement::<Ristretto255>::deserialize(element).map_err(|_| invalid())
            })
            .collect::<Result<Vec<_>, _>>()?;

        VoprfClient::batch_finalize(&inputs, &self.0, &messages, &proof, public_key)
            .map_err(|_| invalid())?
            .map(|output| {
                let mut output = output.map_err(|_| invalid())?;
                // The library's copy is not zeroized on drop.
                let mut bytes = Zeroizing::new([0_u8; OUTPUT_BYTES]);
                bytes.copy_from_slice(&output);
                output.as_mut_slice().zeroize();
                Ok(bytes)
            })
            .collect()
    }
}

/// Adapts `getrandom` to the RNG traits `voprf` needs. `fill_bytes` cannot fail, so a failure is
/// recorded for the caller to discard the result; the non-zero filler keeps the library's
/// zero-scalar rejection loop finite.
#[derive(Default)]
struct SystemRng {
    failed: bool,
}

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        if getrandom::fill(destination).is_err() {
            self.failed = true;
            destination.fill(0xA5);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for SystemRng {}
