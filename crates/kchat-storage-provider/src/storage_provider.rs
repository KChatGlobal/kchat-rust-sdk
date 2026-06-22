use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    time::Duration,
};

use openmls_traits::storage::{Key, StorageProvider, traits};
use r2d2::{ManageConnection, Pool, PooledConnection};
use refinery::error::WrapMigrationError;
use rusqlite::Connection;

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    encryption_key_pairs::{
        StorableEncryptionKeyPair, StorableEncryptionKeyPairRef, StorableEncryptionPublicKeyRef,
    },
    epoch_key_pairs::{StorableEpochKeyPairs, StorableEpochKeyPairsRef},
    group_data::{GroupDataType, StorableGroupData, StorableGroupDataRef},
    group_epoch_message_secrets::StorableGroupEpochMessageSecrets,
    key_packages::{StorableHashRef, StorableKeyPackage, StorableKeyPackageRef},
    own_leaf_nodes::{StorableLeafNode, StorableLeafNodeRef},
    proposals::{StorableProposal, StorableProposalRef},
    psks::{StorablePskBundle, StorablePskBundleRef, StorablePskIdRef},
    signature_key_pairs::{
        StorableSignatureKeyPairs, StorableSignatureKeyPairsRef, StorableSignaturePublicKeyRef,
    },
};

refinery::embed_migrations!("migrations");

/// Storage provider for OpenMLS using Sqlite through the `rusqlite` crate.
/// Implements the [`StorageProvider`] trait. The codec used by the storage
/// provider is set by the generic parameter `C`.
pub struct SqliteStorageProvider<C: Codec> {
    connection: SqliteConnectionPool,
    _codec: PhantomData<C>,
}

impl<C: Codec> Clone for SqliteStorageProvider<C> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            _codec: PhantomData,
        }
    }
}

pub struct TransactionalStorageProvider<'tx, C: Codec> {
    tx: &'tx rusqlite::Transaction<'tx>,
    _codec: PhantomData<C>,
}

type ConnectionOpener = dyn Fn() -> Result<Connection, rusqlite::Error> + Send + Sync;

const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

struct R2d2ConnectionManager {
    opener: std::sync::Arc<ConnectionOpener>,
}

#[derive(Clone)]
pub struct SqliteConnectionPool {
    pool: Pool<R2d2ConnectionManager>,
}

pub struct ConnectionLease {
    connection: PooledConnection<R2d2ConnectionManager>,
}

impl ManageConnection for R2d2ConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        (self.opener)()
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.execute_batch("")?;
        Ok(())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

fn pool_checkout_error(error: r2d2::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

impl SqliteConnectionPool {
    pub fn new<F>(max_size: usize, opener: F) -> Self
    where
        F: Fn() -> Result<Connection, rusqlite::Error> + Send + Sync + 'static,
    {
        let manager = R2d2ConnectionManager {
            opener: std::sync::Arc::new(opener),
        };

        Self {
            pool: Pool::builder()
                .max_size(max_size.max(1) as u32)
                .connection_timeout(POOL_ACQUIRE_TIMEOUT)
                .build_unchecked(manager),
        }
    }

    pub fn checkout(&self) -> Result<ConnectionLease, rusqlite::Error> {
        Ok(ConnectionLease {
            connection: self.pool.get().map_err(pool_checkout_error)?,
        })
    }

    pub fn transaction<F, T>(&self, f: F) -> Result<T, rusqlite::Error>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<T, rusqlite::Error>,
    {
        let mut connection = self.checkout()?;
        let tx = connection.transaction()?;
        tx.busy_timeout(Duration::from_millis(5000))?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}

impl Deref for ConnectionLease {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for ConnectionLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

impl<C: Codec> SqliteStorageProvider<C> {
    /// Create a new instance of the [`SqliteStorageProvider`].
    pub fn new(connection: SqliteConnectionPool) -> Self {
        Self {
            connection,
            _codec: PhantomData,
        }
    }

    pub fn connection_pool(&self) -> SqliteConnectionPool {
        self.connection.clone()
    }
}

impl<C: Codec> SqliteStorageProvider<C> {
    /// Initialize the database with the necessary tables.
    pub fn run_migrations(&mut self) -> Result<(), refinery::Error> {
        let mut runner = migrations::runner().set_abort_divergent(false);
        runner.set_migration_table_name("openmls_sqlite_storage_migrations");

        let mut connection = self.connection.checkout().migration_err(
            "failed to acquire pooled sqlite connection for migrations",
            None,
        )?;
        runner.run(&mut *connection)?;
        Ok(())
    }

    /// Execute a closure within a single SQLite transaction.
    ///
    /// One pooled SQLite connection is acquired once for the entire duration of
    /// the closure.
    /// On success the transaction is committed. On error it is rolled back
    /// automatically when the [`rusqlite::Transaction`] is dropped.
    ///
    /// Use this to wrap multi-step MLS operations (e.g. commit processing,
    /// group creation) so that all storage writes are atomic — a crash or
    /// error mid-sequence will not leave the database in a partially-updated
    /// state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// provider.storage().transaction(|tx| {
    ///     tx.execute("DELETE FROM some_table WHERE id = ?1", [42])?;
    ///     Ok(())
    /// })?;
    /// ```
    pub fn transaction<F, T>(&self, f: F) -> Result<T, rusqlite::Error>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<T, rusqlite::Error>,
    {
        self.connection.transaction(f)
    }
}

impl<'tx, C: Codec> TransactionalStorageProvider<'tx, C> {
    pub fn new(tx: &'tx rusqlite::Transaction<'tx>) -> Self {
        Self {
            tx,
            _codec: PhantomData,
        }
    }

    pub(crate) fn tx(&self) -> &'tx rusqlite::Transaction<'tx> {
        self.tx
    }
}

pub(super) struct StorableGroupIdRef<'a, GroupId: Key<STORAGE_PROVIDER_VERSION>>(pub &'a GroupId);

impl<C: Codec> StorageProvider<STORAGE_PROVIDER_VERSION> for SqliteStorageProvider<C> {
    type Error = rusqlite::Error;

    fn write_mls_join_config<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(config).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::JoinGroupConfig,
        )
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        StorableLeafNodeRef(leaf_node).store::<C, _>(&self.connection, group_id)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        StorableProposalRef(proposal_ref, proposal).store::<C, _>(&self.connection, group_id)
    }

    fn write_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(tree).store::<C, _>(&self.connection, group_id, GroupDataType::Tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(interim_transcript_hash).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::InterimTranscriptHash,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_context).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::Context,
        )
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(confirmation_tag).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::ConfirmationTag,
        )
    }

    fn write_group_state<
        GroupState: traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_state).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::GroupState,
        )
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(message_secrets).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::MessageSecrets,
        )?;
        Ok(())
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(resumption_psk_store).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::ResumptionPskStore,
        )
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(own_leaf_index).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::OwnLeafIndex,
        )?;
        Ok(())
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_epoch_secrets).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::GroupEpochSecrets,
        )?;
        Ok(())
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        StorableSignatureKeyPairsRef(signature_key_pair).store::<C, _>(&self.connection, public_key)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        StorableEncryptionKeyPairRef(key_pair).store::<C, _>(&self.connection, public_key)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        StorableEpochKeyPairsRef(key_pairs).store::<C, _, _>(
            &self.connection,
            group_id,
            epoch,
            leaf_index,
        )
    }

    fn write_key_package<
        HashReference: traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        StorableKeyPackageRef(key_package).store::<C, _>(&self.connection, hash_ref)
    }

    fn write_psk<
        PskId: traits::PskId<STORAGE_PROVIDER_VERSION>,
        PskBundle: traits::PskBundle<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        StorablePskBundleRef(psk).store::<C, _>(&self.connection, psk_id)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        StorableGroupData::load::<C, _>(&self.connection, group_id, GroupDataType::JoinGroupConfig)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        StorableLeafNode::load::<C, _>(&self.connection, group_id)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        StorableProposal::<u8, ProposalRef>::load_refs::<C, _>(&self.connection, group_id)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        StorableProposal::load::<C, _>(&self.connection, group_id)
    }

    fn tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        StorableGroupData::load::<C, _>(&self.connection, group_id, GroupDataType::Tree)
    }

    fn group_context<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        StorableGroupData::load::<C, _>(&self.connection, group_id, GroupDataType::Context)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        StorableGroupData::load::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::InterimTranscriptHash,
        )
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        StorableGroupData::load::<C, _>(&self.connection, group_id, GroupDataType::ConfirmationTag)
    }

    fn group_state<
        GroupState: traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        StorableGroupData::load::<C, _>(&self.connection, group_id, GroupDataType::GroupState)
    }

    fn message_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        StorableGroupData::load::<C, _>(&self.connection, group_id, GroupDataType::MessageSecrets)
    }

    fn supports_epoch_message_secrets(&self) -> bool {
        true
    }

    fn is_group_epoch_message_secrets_migrated<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, Self::Error> {
        StorableGroupEpochMessageSecrets::is_migration_done::<C, _>(&self.connection, group_id)
    }

    fn group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        StorableGroupEpochMessageSecrets::load::<C, _>(&self.connection, group_id, epoch)
    }

    fn write_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
        message_secrets: &[u8],
    ) -> Result<(), Self::Error> {
        StorableGroupEpochMessageSecrets::store::<C, _>(
            &self.connection,
            group_id,
            epoch,
            message_secrets,
        )
    }

    fn replace_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_secrets: Vec<(u64, Vec<u8>)>,
    ) -> Result<(), Self::Error> {
        self.connection.transaction(|tx| {
            StorableGroupEpochMessageSecrets::replace_in_tx::<C, _>(tx, group_id, message_secrets)
        })
    }

    fn mark_group_epoch_message_secrets_migrated<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        _done: bool,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn delete_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupEpochMessageSecrets::delete::<C, _>(&self.connection, group_id)
    }

    fn prune_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        keep_from_epoch: u64,
        current_epoch: u64,
    ) -> Result<(), Self::Error> {
        StorableGroupEpochMessageSecrets::prune::<C, _>(
            &self.connection,
            group_id,
            keep_from_epoch,
            current_epoch,
        )
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        StorableGroupData::load::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::ResumptionPskStore,
        )
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        StorableGroupData::load::<C, _>(&self.connection, group_id, GroupDataType::OwnLeafIndex)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        StorableGroupData::load::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::GroupEpochSecrets,
        )
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        StorableSignatureKeyPairs::load::<C, _>(&self.connection, public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        StorableEncryptionKeyPair::load::<C, _>(&self.connection, public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        StorableEpochKeyPairs::load::<C, _, _>(&self.connection, group_id, epoch, leaf_index)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        StorableKeyPackage::load::<C, _>(&self.connection, hash_ref)
    }

    fn psk<
        PskBundle: traits::PskBundle<STORAGE_PROVIDER_VERSION>,
        PskId: traits::PskId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        StorablePskBundle::load::<C, _>(&self.connection, psk_id)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_proposal::<C, _>(&self.connection, proposal_ref)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_leaf_nodes::<C>(&self.connection)
    }

    fn delete_group_config<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::JoinGroupConfig)
    }

    fn delete_tree<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_group_data::<C>(&self.connection, GroupDataType::Tree)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::ConfirmationTag)
    }

    fn delete_group_state<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::GroupState)
    }

    fn delete_context<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::Context)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::InterimTranscriptHash)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::MessageSecrets)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::ResumptionPskStore)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::OwnLeafIndex)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::GroupEpochSecrets)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_all_proposals::<C>(&self.connection)?;
        Ok(())
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        StorableSignaturePublicKeyRef(public_key).delete::<C>(&self.connection)
    }

    fn delete_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        StorableEncryptionPublicKeyRef(public_key).delete::<C>(&self.connection)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_epoch_key_pair::<C, _>(
            &self.connection,
            epoch,
            leaf_index,
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<STORAGE_PROVIDER_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        StorableHashRef(hash_ref).delete_key_package::<C>(&self.connection)
    }

    fn delete_psk<PskKey: traits::PskId<STORAGE_PROVIDER_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        StorablePskIdRef(psk_id).delete::<C>(&self.connection)
    }

    #[cfg(feature = "extensions-draft-08")]
    fn write_application_export_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(application_export_tree).store::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::ApplicationExportTree,
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    fn application_export_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        StorableGroupData::load::<C, _>(
            &self.connection,
            group_id,
            GroupDataType::ApplicationExportTree,
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    fn delete_application_export_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(&self.connection, GroupDataType::ApplicationExportTree)
    }
}

impl<'tx, C: Codec> StorageProvider<STORAGE_PROVIDER_VERSION>
    for TransactionalStorageProvider<'tx, C>
{
    type Error = rusqlite::Error;

    fn write_mls_join_config<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(config).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::JoinGroupConfig,
        )
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        StorableLeafNodeRef(leaf_node).store_in_tx::<C, _>(self.tx, group_id)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        StorableProposalRef(proposal_ref, proposal).store_in_tx::<C, _>(self.tx, group_id)
    }

    fn write_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(tree).store_in_tx::<C, _>(self.tx, group_id, GroupDataType::Tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(interim_transcript_hash).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::InterimTranscriptHash,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_context).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::Context,
        )
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(confirmation_tag).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::ConfirmationTag,
        )
    }

    fn write_group_state<
        GroupState: traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_state).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::GroupState,
        )
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(message_secrets).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::MessageSecrets,
        )
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(resumption_psk_store).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::ResumptionPskStore,
        )
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(own_leaf_index).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::OwnLeafIndex,
        )
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_epoch_secrets).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::GroupEpochSecrets,
        )
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        StorableSignatureKeyPairsRef(signature_key_pair).store_in_tx::<C, _>(self.tx, public_key)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        StorableEncryptionKeyPairRef(key_pair).store_in_tx::<C, _>(self.tx, public_key)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        StorableEpochKeyPairsRef(key_pairs)
            .store_in_tx::<C, _, _>(self.tx, group_id, epoch, leaf_index)
    }

    fn write_key_package<
        HashReference: traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        StorableKeyPackageRef(key_package).store_in_tx::<C, _>(self.tx, hash_ref)
    }

    fn write_psk<
        PskId: traits::PskId<STORAGE_PROVIDER_VERSION>,
        PskBundle: traits::PskBundle<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        StorablePskBundleRef(psk).store_in_tx::<C, _>(self.tx, psk_id)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::JoinGroupConfig)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        StorableLeafNode::load_in_tx::<C, _>(self.tx, group_id)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        StorableProposal::<u8, ProposalRef>::load_refs_in_tx::<C, _>(self.tx, group_id)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        StorableProposal::load_in_tx::<C, _>(self.tx, group_id)
    }

    fn tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::Tree)
    }

    fn group_context<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::Context)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::InterimTranscriptHash,
        )
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::ConfirmationTag)
    }

    fn group_state<
        GroupState: traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::GroupState)
    }

    fn message_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::MessageSecrets)
    }

    fn supports_epoch_message_secrets(&self) -> bool {
        true
    }

    fn is_group_epoch_message_secrets_migrated<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, Self::Error> {
        StorableGroupEpochMessageSecrets::is_migration_done_in_tx::<C, _>(self.tx, group_id)
    }

    fn group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        StorableGroupEpochMessageSecrets::load_in_tx::<C, _>(self.tx, group_id, epoch)
    }

    fn write_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        epoch: u64,
        message_secrets: &[u8],
    ) -> Result<(), Self::Error> {
        StorableGroupEpochMessageSecrets::store_in_tx::<C, _>(
            self.tx,
            group_id,
            epoch,
            message_secrets,
        )
    }

    fn replace_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        message_secrets: Vec<(u64, Vec<u8>)>,
    ) -> Result<(), Self::Error> {
        StorableGroupEpochMessageSecrets::replace_in_tx::<C, _>(self.tx, group_id, message_secrets)
    }

    fn mark_group_epoch_message_secrets_migrated<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        _done: bool,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn delete_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupEpochMessageSecrets::delete_in_tx::<C, _>(self.tx, group_id)
    }

    fn prune_group_epoch_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
        keep_from_epoch: u64,
        current_epoch: u64,
    ) -> Result<(), Self::Error> {
        StorableGroupEpochMessageSecrets::prune_in_tx::<C, _>(
            self.tx,
            group_id,
            keep_from_epoch,
            current_epoch,
        )
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::ResumptionPskStore)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::OwnLeafIndex)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(self.tx, group_id, GroupDataType::GroupEpochSecrets)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        StorableSignatureKeyPairs::load_in_tx::<C, _>(self.tx, public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        StorableEncryptionKeyPair::load_in_tx::<C, _>(self.tx, public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        StorableEpochKeyPairs::load_in_tx::<C, _, _>(self.tx, group_id, epoch, leaf_index)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        StorableKeyPackage::load_in_tx::<C, _>(self.tx, hash_ref)
    }

    fn psk<
        PskBundle: traits::PskBundle<STORAGE_PROVIDER_VERSION>,
        PskId: traits::PskId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        StorablePskBundle::load_in_tx::<C, _>(self.tx, psk_id)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_proposal_in_tx::<C, _>(self.tx, proposal_ref)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_leaf_nodes_in_tx::<C>(self.tx)
    }

    fn delete_group_config<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::JoinGroupConfig)
    }

    fn delete_tree<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_group_data_in_tx::<C>(self.tx, GroupDataType::Tree)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::ConfirmationTag)
    }

    fn delete_group_state<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::GroupState)
    }

    fn delete_context<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_group_data_in_tx::<C>(self.tx, GroupDataType::Context)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::InterimTranscriptHash)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::MessageSecrets)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::ResumptionPskStore)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::OwnLeafIndex)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::GroupEpochSecrets)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_all_proposals_in_tx::<C>(self.tx)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        StorableSignaturePublicKeyRef(public_key).delete_in_tx::<C>(self.tx)
    }

    fn delete_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        StorableEncryptionPublicKeyRef(public_key).delete_in_tx::<C>(self.tx)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_epoch_key_pair_in_tx::<C, _>(self.tx, epoch, leaf_index)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<STORAGE_PROVIDER_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        StorableHashRef(hash_ref).delete_key_package_in_tx::<C>(self.tx)
    }

    fn delete_psk<PskKey: traits::PskId<STORAGE_PROVIDER_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        StorablePskIdRef(psk_id).delete_in_tx::<C>(self.tx)
    }

    #[cfg(feature = "extensions-draft-08")]
    fn write_application_export_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(application_export_tree).store_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::ApplicationExportTree,
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    fn application_export_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        StorableGroupData::load_in_tx::<C, _>(
            self.tx,
            group_id,
            GroupDataType::ApplicationExportTree,
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    fn delete_application_export_tree<
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data_in_tx::<C>(self.tx, GroupDataType::ApplicationExportTree)
    }
}
