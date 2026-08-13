use openmls::prelude::Ciphersuite;

use crate::{core::DEFAULT_CIPHERSUITE, error::Error};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KchatCiphersuite {
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = DEFAULT_CIPHERSUITE as u16,
    MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 =
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 as u16,
    MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 =
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 as u16,
}

pub const SDK_SUPPORTED_CIPHERSUITES: [KchatCiphersuite; 3] = [
    KchatCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    KchatCiphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
    KchatCiphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
];

impl KchatCiphersuite {
    pub fn to_openmls(self) -> Ciphersuite {
        match self {
            Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => DEFAULT_CIPHERSUITE,
            Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            }
            Self::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => {
                Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
            }
        }
    }

    pub fn from_u16(value: u16) -> Result<Self, Error> {
        let ciphersuite = Ciphersuite::try_from(value)
            .map_err(|err| Error::UnsupportedCiphersuite(err.to_string()))?;

        match ciphersuite {
            c if c == DEFAULT_CIPHERSUITE => {
                Ok(Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
            }
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                Ok(Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            }
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => {
                Ok(Self::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87)
            }
            other => Err(Error::UnsupportedCiphersuite(format!("{other:?}"))),
        }
    }
}

pub fn requires_external_ratchet_tree(ciphersuite: Ciphersuite) -> bool {
    ciphersuite == Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
}

pub fn ensure_supported_ciphersuite(ciphersuite: Ciphersuite) -> Result<(), Error> {
    KchatCiphersuite::from_u16(ciphersuite as u16).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_pq_requires_external_ratchet_tree() {
        assert!(requires_external_ratchet_tree(
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
        ));
    }

    #[test]
    fn classic_and_xwing_do_not_require_external_ratchet_tree() {
        assert!(!requires_external_ratchet_tree(DEFAULT_CIPHERSUITE));
        assert!(!requires_external_ratchet_tree(
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
        ));
    }

    #[test]
    fn sdk_suite_policy_accepts_the_three_supported_suites() {
        for suite in SDK_SUPPORTED_CIPHERSUITES {
            assert!(ensure_supported_ciphersuite(suite.to_openmls()).is_ok());
        }
    }

    #[test]
    fn sdk_suite_policy_rejects_an_unlisted_suite() {
        assert!(
            ensure_supported_ciphersuite(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
                .is_err()
        );
    }
}
