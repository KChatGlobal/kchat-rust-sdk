use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use openmls_traits::storage::{Entity, Key, traits::SignaturePublicKey as SignaturePublicKeyTrait};
use rusqlite::{OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>(
    pub SignatureKeyPairs,
);

impl<SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>
    StorableSignatureKeyPairs<SignatureKeyPairs>
{
    pub(super) fn load<
        C: Codec,
        SignaturePublicKey: SignaturePublicKeyTrait<STORAGE_PROVIDER_VERSION>,
    >(
        connection: &Arc<Mutex<rusqlite::Connection>>,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPairs>, rusqlite::Error> {
        let signature_key = connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT signature_key
                FROM openmls_signature_keys
                WHERE public_key = ?1
                    AND provider_version = ?2",
                params![
                    KeyRefWrapper::<C, _>(public_key, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| {
                    let EntityWrapper::<C, _>(signature_key, ..) = row.get(0)?;
                    Ok(signature_key)
                },
            )
            .optional()?;
        Ok(signature_key)
    }
}

pub(crate) struct StorableSignatureKeyPairsRef<
    'a,
    SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>,
>(pub &'a SignatureKeyPairs);

impl<SignatureKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>
    StorableSignatureKeyPairsRef<'_, SignatureKeyPairs>
{
    pub(super) fn store<C: Codec, SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Arc<Mutex<rusqlite::Connection>>,
        public_key: &SignaturePublicKey,
    ) -> Result<(), rusqlite::Error> {
        connection.lock().unwrap().execute(
            "INSERT OR REPLACE INTO openmls_signature_keys (public_key, signature_key, provider_version)
            VALUES (?1, ?2, ?3)",
            params![
                KeyRefWrapper::<C, _>(public_key, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}

pub(super) struct StorableSignaturePublicKeyRef<
    'a,
    SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>,
>(pub &'a SignaturePublicKey);

impl<SignaturePublicKey: Key<STORAGE_PROVIDER_VERSION>>
    StorableSignaturePublicKeyRef<'_, SignaturePublicKey>
{
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &Arc<Mutex<rusqlite::Connection>>,
    ) -> Result<(), rusqlite::Error> {
        connection.lock().unwrap().execute(
            "DELETE FROM openmls_signature_keys
            WHERE public_key = ?1
                AND provider_version = ?2",
            params![
                KeyRefWrapper::<C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}
