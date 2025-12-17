use openmls::{
    group::{Member, MlsGroup},
    prelude::{BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::error::Error;

pub(crate) fn find_members_by_identity<'a>(
    members: &'a [Member],
    identities: &[&[u8]],
) -> Vec<&'a Member> {
    let mut result = Vec::new();

    for member in members {
        if let Ok(member_credential) = BasicCredential::try_from(member.credential.clone()) {
            if identities.contains(&member_credential.identity()) {
                result.push(member);
            }
        }
    }

    result
}

pub(crate) fn get_own_signature_key_from_group<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
) -> Result<SignatureKeyPair, Error> {
    let own_leaf = group.own_leaf().ok_or(Error::MissingOwnLeafNodeInGroup)?;
    let public_key = own_leaf.signature_key().as_slice();

    SignatureKeyPair::read(
        provider.storage(),
        public_key,
        group.ciphersuite().signature_algorithm(),
    )
    .ok_or(Error::MissingSignatureKeyPair)
}

pub(crate) fn get_identity_from_key_packages(key_packages: &[KeyPackage]) -> Vec<Vec<u8>> {
    let mut ids = Vec::new();

    for key_package in key_packages {
        if let Ok(member_credential) =
            BasicCredential::try_from(key_package.leaf_node().credential().clone())
        {
            ids.push(member_credential.identity().to_owned());
        }
    }

    ids
}

// Get a basic credential and a signature key from public key.
// If input public_key is None then generating new signature key.
pub(crate) fn get_credential_with_key<Provider: OpenMlsProvider>(
    user_id: &str,
    provider: &Provider,
    ciphersuite: Ciphersuite,
    public_key: Option<Vec<u8>>,
) -> Result<(CredentialWithKey, SignatureKeyPair), Error> {
    let credential = BasicCredential::new(user_id.into());
    let signature_scheme = ciphersuite.signature_algorithm();
    let signature_key = if let Some(public_key) = public_key {
        SignatureKeyPair::read(provider.storage(), &public_key, signature_scheme)
            .ok_or(Error::MissingSignatureKeyPair)?
    } else {
        SignatureKeyPair::new(signature_scheme)?
    };

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_key.to_public_vec().into(),
    };

    signature_key
        .store(provider.storage())
        .map_err(|e| Error::Storage(e.to_string()))?;

    Ok((credential_with_key, signature_key))
}
