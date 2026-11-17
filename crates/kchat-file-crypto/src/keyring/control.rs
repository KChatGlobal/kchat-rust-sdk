use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    ControlAuthority, ControlOutcome, ControlPeer, ControlRecipient, ControlRequest,
    FileCryptoError, KeySyncRequest, MAX_ROOT_KEYS_PER_MESSAGE, OutgoingControlMessage, RootId,
    RootKind, TenantId,
    control::{
        DecodedControl, EVENT_ID_BYTES, KeySyncMessage, NODE_KEY_DISTRIBUTION, PEPPER_DISTRIBUTION,
        PepperDistribution, RootKeyDistribution, decode_control, encode_key_sync_request,
        encode_pepper_distribution, encode_root_keys,
    },
    ids::validate_id,
    key_tree::validate_generation,
};

use super::{
    FileKeyring,
    node_keys::{
        NewRow, SOURCE_RECEIVED, STATE_ACTIVE, active_root_key, active_root_keys, check_root,
        load_key, store_received_key,
    },
    now_unix_seconds,
    peppers::{active_pepper_at, store_received_pepper},
};

const RESULT_IMPORTED: &str = "imported";
const PROCESSED_EVENT_RETENTION_SECONDS: i64 = 90 * 24 * 60 * 60;

impl FileKeyring {
    /// Packs active pepper `generation` of `tenant` for `recipient` (`PepperRequired` if it is not
    /// active). The host must check that `recipient` is a tenant member.
    pub fn build_pepper_distribution(
        &self,
        tenant: &TenantId,
        generation: u64,
        recipient: &ControlRecipient,
    ) -> Result<OutgoingControlMessage, FileCryptoError> {
        let pepper = active_pepper_at(&*self.lock()?, tenant, generation)?
            .ok_or_else(FileCryptoError::pepper_required)?;
        encode_pepper_distribution(tenant, recipient, &pepper)
    }

    /// Packs active root key `epoch` of `root`, typically right after winning a rotation CAS.
    /// Group roots may use `recipient = None` (the whole MLS group); personal roots must name this
    /// account. A wrong recipient or a pending key returns `PolicyViolation`.
    pub fn build_root_key_distribution(
        &self,
        root: &RootId,
        epoch: u64,
        recipient: Option<&ControlRecipient>,
    ) -> Result<OutgoingControlMessage, FileCryptoError> {
        validate_generation(epoch)?;
        self.check_root_recipient(root, recipient)?;
        let entry = {
            let connection = self.lock()?;
            check_root(&connection, root)?;
            active_root_key(&connection, root, epoch, FileCryptoError::policy_violation)?
        };
        encode_root_keys(root, recipient, &[entry])
    }

    /// Packs the active epochs of `root` for `recipient`, e.g. a new member who needs old epochs.
    /// The host must check membership first. Only the newest [`MAX_ROOT_KEYS_PER_MESSAGE`] epochs
    /// fit; the recipient asks for older ones with `build_key_sync_request`.
    pub fn build_root_key_bundle(
        &self,
        root: &RootId,
        recipient: &ControlRecipient,
    ) -> Result<OutgoingControlMessage, FileCryptoError> {
        self.check_root_recipient(root, Some(recipient))?;
        let keys = {
            let connection = self.lock()?;
            check_root(&connection, root)?;
            active_root_keys(&connection, root, MAX_ROOT_KEYS_PER_MESSAGE)?
        };
        if keys.is_empty() {
            return Err(FileCryptoError::key_sync_required());
        }
        encode_root_keys(root, Some(recipient), &keys)
    }

    /// Asks for root keys of `root` at `epochs` after a `KeySyncRequired`. Recipient rules are those
    /// of `build_root_key_distribution`; the message carries no keys.
    pub fn build_key_sync_request(
        &self,
        root: &RootId,
        epochs: &[u64],
        recipient: Option<&ControlRecipient>,
    ) -> Result<OutgoingControlMessage, FileCryptoError> {
        self.check_root_recipient(root, recipient)?;
        check_root(&*self.lock()?, root)?;
        encode_key_sync_request(root, recipient, epochs)
    }

    /// Answers `ControlOutcome::KeySyncRequested` with the requested epochs this device holds
    /// **and** `authority` allows, addressed to the requesting device. Returns `KeySyncRequired`
    /// if none is held and `UnauthorizedSender` if none is allowed.
    pub fn build_key_sync_response(
        &self,
        request: &KeySyncRequest,
        authority: &dyn ControlAuthority,
    ) -> Result<OutgoingControlMessage, FileCryptoError> {
        let (root, requester) = (request.root(), request.requester());
        // Hard check: personal roots never go to another account, whatever the host says.
        if !self.may_hold(root, requester.account_id()) {
            return Err(FileCryptoError::unauthorized_sender());
        }

        let mut held = Vec::with_capacity(request.epochs().len());
        {
            let connection = self.lock()?;
            check_root(&connection, root)?;
            for &epoch in request.epochs() {
                if load_key(&connection, root.tenant(), root.node_id(), epoch)?
                    .is_some_and(|stored| stored.active)
                {
                    held.push(epoch);
                }
            }
        }
        if held.is_empty() {
            return Err(FileCryptoError::key_sync_required());
        }

        // Ask the host per epoch, without holding the store lock.
        let allowed: Vec<u64> = held
            .into_iter()
            .filter(|&epoch| {
                authority.allow(requester, &ControlRequest::KeySyncRequest { root, epoch })
            })
            .collect();
        if allowed.is_empty() {
            return Err(FileCryptoError::unauthorized_sender());
        }

        let keys = {
            let connection = self.lock()?;
            allowed
                .into_iter()
                .map(|epoch| {
                    active_root_key(&connection, root, epoch, FileCryptoError::invalid_state)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let recipient = ControlRecipient::device(requester.account_id(), requester.device_id())?;
        encode_root_keys(root, Some(&recipient), &keys)
    }

    /// Processes a control message received over MLS and stores its keys. `sender` is the
    /// MLS-authenticated sender; `local_device_id` checks device-addressed messages. See the module
    /// docs for error handling.
    pub fn process_control(
        &self,
        sender: &ControlPeer,
        local_device_id: &str,
        message: &[u8],
        authority: &dyn ControlAuthority,
    ) -> Result<ControlOutcome, FileCryptoError> {
        validate_id(local_device_id)?;
        match decode_control(message)? {
            DecodedControl::Pepper(distribution) => {
                self.process_pepper(sender, local_device_id, &distribution, authority)
            }
            DecodedControl::RootKeys(distribution) => {
                self.process_root_keys(sender, local_device_id, &distribution, authority)
            }
            DecodedControl::KeySync(message) => {
                self.process_key_sync_request(sender, local_device_id, message)
            }
        }
    }

    /// Only checked, never stored (answering twice is harmless); `build_key_sync_response` asks
    /// the host per epoch.
    fn process_key_sync_request(
        &self,
        sender: &ControlPeer,
        local_device_id: &str,
        message: KeySyncMessage,
    ) -> Result<ControlOutcome, FileCryptoError> {
        self.check_addressed(message.recipient.as_ref(), local_device_id)?;
        if !self.may_hold(&message.root, sender.account_id()) {
            return Err(FileCryptoError::unauthorized_sender());
        }
        Ok(ControlOutcome::KeySyncRequested(
            message.with_requester(sender),
        ))
    }

    fn process_pepper(
        &self,
        sender: &ControlPeer,
        local_device_id: &str,
        distribution: &PepperDistribution,
        authority: &dyn ControlAuthority,
    ) -> Result<ControlOutcome, FileCryptoError> {
        let PepperDistribution {
            event_id,
            tenant,
            recipient,
            pepper,
            commitment,
        } = distribution;
        self.check_addressed(Some(recipient), local_device_id)?;
        if is_processed(&*self.lock()?, event_id)? {
            return Ok(ControlOutcome::AlreadyProcessed);
        }

        // The host is called without the store lock: it may call back into `FileKeyring`.
        let generation = pepper.generation();
        if !authority.allow(
            sender,
            &ControlRequest::PepperDistribution { tenant, generation },
        ) {
            return Err(FileCryptoError::unauthorized_sender());
        }
        // Only the pepper that won the server CAS is valid.
        let published = authority
            .published_pepper_commitment(tenant, generation)
            .ok_or_else(FileCryptoError::key_config_required)?;
        if published != *commitment {
            return Err(FileCryptoError::key_conflict());
        }

        let imported = self.import_event(event_id, PEPPER_DISTRIBUTION, sender, tenant, |tx| {
            store_received_pepper(tx, tenant, pepper)
        })?;
        Ok(if imported {
            ControlOutcome::PepperImported {
                tenant: tenant.clone(),
                generation,
            }
        } else {
            ControlOutcome::AlreadyProcessed
        })
    }

    fn process_root_keys(
        &self,
        sender: &ControlPeer,
        local_device_id: &str,
        distribution: &RootKeyDistribution,
        authority: &dyn ControlAuthority,
    ) -> Result<ControlOutcome, FileCryptoError> {
        let RootKeyDistribution {
            event_id,
            root,
            recipient,
            keys,
        } = distribution;
        self.check_addressed(recipient.as_ref(), local_device_id)?;
        if is_processed(&*self.lock()?, event_id)? {
            return Ok(ControlOutcome::AlreadyProcessed);
        }

        // Hard check before asking the host: personal keys come only from this account's devices.
        if !self.may_hold(root, sender.account_id()) {
            return Err(FileCryptoError::unauthorized_sender());
        }
        let epochs: Vec<u64> = keys.iter().map(|entry| entry.epoch).collect();
        let request = ControlRequest::RootKeyDistribution {
            root,
            epochs: &epochs,
        };
        if !authority.allow(sender, &request) {
            return Err(FileCryptoError::unauthorized_sender());
        }
        // Only the key that won the server CAS for each epoch is valid.
        for entry in keys {
            let published = authority
                .published_root_key_hash(root, entry.epoch)
                .ok_or_else(FileCryptoError::key_config_required)?;
            if published != entry.key_hash {
                return Err(FileCryptoError::key_conflict());
            }
        }

        let (tenant, node) = (root.tenant(), root.node_id());
        let imported =
            self.import_event(event_id, NODE_KEY_DISTRIBUTION, sender, tenant, |tx| {
                check_root(tx, root)?;
                // One failing epoch (e.g. `KeyConflict`) rolls back the whole message.
                keys.iter().try_for_each(|entry| {
                    store_received_key(
                        tx,
                        &NewRow {
                            tenant,
                            node_id: node,
                            generation: entry.epoch,
                            kind: root.kind().node_kind(),
                            root_id: node,
                            root_epoch: None,
                            key: &entry.key,
                            key_hash: &entry.key_hash,
                            state: STATE_ACTIVE,
                            source: SOURCE_RECEIVED,
                        },
                    )
                })
            })?;
        Ok(if imported {
            ControlOutcome::RootKeysImported {
                root: root.clone(),
                epochs,
            }
        } else {
            ControlOutcome::AlreadyProcessed
        })
    }

    /// Runs `store` and records `event_id` in one transaction. Returns `false` if another handle
    /// processed the event first.
    fn import_event(
        &self,
        event_id: &[u8; EVENT_ID_BYTES],
        kind: &str,
        sender: &ControlPeer,
        tenant: &TenantId,
        store: impl FnOnce(&Connection) -> Result<(), FileCryptoError>,
    ) -> Result<bool, FileCryptoError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if is_processed(&transaction, event_id)? {
            return Ok(false);
        }
        store(&transaction)?;
        mark_processed(&transaction, event_id, kind, sender, tenant)?;
        transaction.commit()?;
        Ok(true)
    }

    /// `None` addresses the whole MLS group carrying the message.
    fn check_addressed(
        &self,
        recipient: Option<&ControlRecipient>,
        local_device_id: &str,
    ) -> Result<(), FileCryptoError> {
        let addressed = recipient.is_none_or(|recipient| {
            recipient.account_id() == self.account_id
                && recipient
                    .device_id()
                    .is_none_or(|device| device == local_device_id)
        });
        if addressed {
            Ok(())
        } else {
            Err(FileCryptoError::wrong_recipient())
        }
    }

    /// Whether `account_id` may hold keys of `root`: personal keys never leave this account.
    fn may_hold(&self, root: &RootId, account_id: &str) -> bool {
        root.kind() == RootKind::Group || account_id == self.account_id
    }

    /// Personal roots must be addressed to this account, never to a whole group.
    fn check_root_recipient(
        &self,
        root: &RootId,
        recipient: Option<&ControlRecipient>,
    ) -> Result<(), FileCryptoError> {
        let allowed = recipient.map_or(root.kind() == RootKind::Group, |recipient| {
            self.may_hold(root, recipient.account_id())
        });
        if allowed {
            Ok(())
        } else {
            Err(FileCryptoError::policy_violation())
        }
    }
}

fn is_processed(
    connection: &Connection,
    event_id: &[u8; EVENT_ID_BYTES],
) -> Result<bool, FileCryptoError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM processed_events WHERE event_id = ?1",
            [event_id.as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Records an imported event and forgets events past the retention period. Forgetting is safe:
/// importing the same keys again is a no-op, and `ControlAuthority` refuses a sender who has since
/// lost its rights.
fn mark_processed(
    connection: &Connection,
    event_id: &[u8; EVENT_ID_BYTES],
    kind: &str,
    sender: &ControlPeer,
    tenant: &TenantId,
) -> Result<(), FileCryptoError> {
    let now = now_unix_seconds();
    connection.execute(
        "DELETE FROM processed_events WHERE processed_at < ?1",
        [now.saturating_sub(PROCESSED_EVENT_RETENTION_SECONDS)],
    )?;
    connection.execute(
        "INSERT INTO processed_events (event_id, kind, sender_account, sender_device, \
         tenant, result, processed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event_id.as_slice(),
            kind,
            sender.account_id(),
            sender.device_id(),
            tenant.as_str(),
            RESULT_IMPORTED,
            now
        ],
    )?;
    Ok(())
}
