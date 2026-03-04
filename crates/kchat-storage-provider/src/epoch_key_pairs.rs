use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use openmls_traits::storage::{Entity, Key};
use rusqlite::{OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntitySliceWrapper, EntityVecWrapper, KeyRefWrapper},
};

pub(crate) struct StorableEpochKeyPairs<EpochKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>(
    pub Vec<EpochKeyPairs>,
);

impl<EpochKeyPairs: Entity<STORAGE_PROVIDER_VERSION>> StorableEpochKeyPairs<EpochKeyPairs> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityVecWrapper::<C, _>(key_pairs, ..) = row.get(0)?;
        Ok(Self(key_pairs))
    }

    pub(super) fn load<
        C: Codec,
        GroupId: Key<STORAGE_PROVIDER_VERSION>,
        EpochKey: Key<STORAGE_PROVIDER_VERSION>,
    >(
        connection: &Arc<Mutex<rusqlite::Connection>>,
        group_id: &GroupId,
        epoch_id: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<EpochKeyPairs>, rusqlite::Error> {
        let connection = connection.lock().unwrap();
        let mut stmt = connection.prepare(
            "SELECT key_pairs
            FROM openmls_epoch_keys_pairs
            WHERE group_id = ?1
                AND epoch_id = ?2
                AND leaf_index = ?3
                AND provider_version = ?4",
        )?;
        let result = stmt
            .query_row(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                    leaf_index,
                    STORAGE_PROVIDER_VERSION
                ],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )
            .optional()?
            .unwrap_or_default();
        Ok(result)
    }
}

pub(super) struct StorableEpochKeyPairsRef<'a, EpochKeyPairs: Entity<STORAGE_PROVIDER_VERSION>>(
    pub &'a [EpochKeyPairs],
);

impl<EpochKeyPairs: Entity<STORAGE_PROVIDER_VERSION>> StorableEpochKeyPairsRef<'_, EpochKeyPairs> {
    pub(super) fn store<
        C: Codec,
        GroupId: Key<STORAGE_PROVIDER_VERSION>,
        EpochKey: Key<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &Arc<Mutex<rusqlite::Connection>>,
        group_id: &GroupId,
        epoch_id: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), rusqlite::Error> {
        connection.lock().unwrap().execute(
            "INSERT OR REPLACE INTO openmls_epoch_keys_pairs (group_id, epoch_id, leaf_index, key_pairs, provider_version)
                VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                leaf_index,
                EntitySliceWrapper::<'_, C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}

impl<GroupId: Key<STORAGE_PROVIDER_VERSION>> StorableGroupIdRef<'_, GroupId> {
    pub(super) fn delete_epoch_key_pair<C: Codec, EpochKey: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Arc<Mutex<rusqlite::Connection>>,
        epoch_key: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), rusqlite::Error> {
        connection.lock().unwrap().execute(
            "DELETE FROM openmls_epoch_keys_pairs
            WHERE group_id = ?1
                AND epoch_id = ?2
                AND leaf_index = ?3
                AND provider_version = ?4",
            params![
                KeyRefWrapper::<C, _>(self.0, PhantomData),
                KeyRefWrapper::<C, _>(epoch_key, PhantomData),
                leaf_index,
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}
