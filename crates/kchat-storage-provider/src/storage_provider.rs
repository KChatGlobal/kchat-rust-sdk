use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use openmls_traits::storage::{Key, StorageProvider, traits};
use rusqlite::Connection;

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    encryption_key_pairs::{
        StorableEncryptionKeyPair, StorableEncryptionKeyPairRef, StorableEncryptionPublicKeyRef,
    },
    epoch_key_pairs::{StorableEpochKeyPairs, StorableEpochKeyPairsRef},
    group_data::{GroupDataType, StorableGroupData, StorableGroupDataRef},
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
    connection: Arc<Mutex<Connection>>,
    _codec: PhantomData<C>,
}

impl<C: Codec> SqliteStorageProvider<C> {
    /// Create a new instance of the [`SqliteStorageProvider`].
    pub fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self {
            connection,
            _codec: PhantomData,
        }
    }
}

impl<C: Codec> SqliteStorageProvider<C> {
    /// Initialize the database with the necessary tables.
    pub fn run_migrations(&mut self) -> Result<(), refinery::Error> {
        let mut runner = migrations::runner().set_abort_divergent(false);
        runner.set_migration_table_name("openmls_sqlite_storage_migrations");

        runner.run(&mut *self.connection.lock().unwrap())?;
        Ok(())
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
