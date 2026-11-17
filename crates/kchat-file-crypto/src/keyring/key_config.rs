//! Verified key-service public keys and tenant policies. Per signing root, generations and policy
//! versions never go backwards (even across restarts or root changes), so a replayed old but
//! validly signed configuration is rejected.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    FileCryptoError, KKeyRootKey, KeySourceStatus, ProfilePolicy, TenantId,
    kkey::{
        KKEY_PUBLIC_KEY_BYTES, KKeyElement, decode_public_key, verify_policy, verify_public_key,
    },
};

use super::{
    FileKeyring, from_sql_integer, now_unix_seconds, peppers::active_pepper_generation,
    to_sql_integer,
};

impl FileKeyring {
    /// Verifies and stores the key-service public key for `key_gen`. Re-importing is a no-op; a
    /// lower generation returns `KKeySignatureInvalid`, a different key for a stored generation
    /// `KeyConflict`.
    pub fn import_public_key(
        &self,
        tenant: &TenantId,
        key_gen: u64,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), FileCryptoError> {
        let key_gen_value = to_sql_integer(key_gen)?;
        let encoded =
            verify_public_key(self.root.as_ref(), tenant, key_gen, public_key, signature)?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(FileCryptoError::kkey_signature_invalid)?;

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let highest: Option<i64> = transaction.query_row(
            "SELECT MAX(key_gen) FROM kkey_keys WHERE tenant = ?1",
            [tenant.as_str()],
            |row| row.get(0),
        )?;
        let floor = read_floor(&transaction, root, tenant.as_str(), Floor::KeyGen)?;
        if highest
            .max(floor)
            .is_some_and(|highest| key_gen_value < highest)
        {
            return Err(FileCryptoError::kkey_signature_invalid());
        }
        let stored: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT public_key FROM kkey_keys WHERE tenant = ?1 AND key_gen = ?2",
                params![tenant.as_str(), key_gen_value],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(stored) = stored {
            return if stored == encoded {
                Ok(())
            } else {
                Err(FileCryptoError::key_conflict())
            };
        }
        transaction.execute(
            "INSERT INTO kkey_keys (tenant, key_gen, public_key, signature, received_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tenant.as_str(),
                key_gen_value,
                encoded.as_slice(),
                signature,
                now_unix_seconds()
            ],
        )?;
        raise_floor(
            &transaction,
            root,
            tenant.as_str(),
            Floor::KeyGen,
            key_gen_value,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Verifies and stores the tenant policy; versioning follows [`FileKeyring::import_public_key`].
    pub fn import_policy(
        &self,
        tenant: &TenantId,
        policy_version: u64,
        policy: &str,
        signature: &[u8],
    ) -> Result<(), FileCryptoError> {
        let version_value = to_sql_integer(policy_version)?;
        verify_policy(
            self.root.as_ref(),
            tenant,
            policy_version,
            policy,
            signature,
        )?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(FileCryptoError::kkey_signature_invalid)?;

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let floor = read_floor(&transaction, root, tenant.as_str(), Floor::PolicyVersion)?;
        if floor.is_some_and(|floor| version_value < floor) {
            return Err(FileCryptoError::kkey_signature_invalid());
        }
        let stored: Option<(i64, String)> = transaction
            .query_row(
                "SELECT policy_version, policy FROM kkey_policies WHERE tenant = ?1",
                [tenant.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_version, stored_policy)) = stored {
            if version_value < stored_version {
                return Err(FileCryptoError::kkey_signature_invalid());
            }
            if version_value == stored_version {
                return if stored_policy == policy {
                    Ok(())
                } else {
                    Err(FileCryptoError::key_conflict())
                };
            }
        }
        transaction.execute(
            "INSERT INTO kkey_policies (tenant, policy, policy_version, signature, received_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (tenant) DO UPDATE SET policy = excluded.policy, \
             policy_version = excluded.policy_version, signature = excluded.signature, \
             received_at = excluded.received_at",
            params![
                tenant.as_str(),
                policy,
                version_value,
                signature,
                now_unix_seconds()
            ],
        )?;
        raise_floor(
            &transaction,
            root,
            tenant.as_str(),
            Floor::PolicyVersion,
            version_value,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn key_source_status(&self, tenant: &TenantId) -> Result<KeySourceStatus, FileCryptoError> {
        let connection = self.lock()?;
        let (policy, policy_version) = stored_policy(&connection, tenant)?.unzip();
        Ok(KeySourceStatus {
            policy,
            policy_version,
            key_gen: highest_public_key(&connection, tenant)?.map(|(key_gen, _)| key_gen),
            pepper_gen: active_pepper_generation(&connection, tenant)?,
        })
    }
}

/// Deletes stored public keys and policies that `root` does not sign, so a replaced or revoked
/// root's configuration is never used. Rollback floors are kept: imports already raised them.
pub(super) fn prune_untrusted_key_config(
    connection: &mut Connection,
    root: Option<&KKeyRootKey>,
) -> Result<(), FileCryptoError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let keys: Vec<(String, i64, Vec<u8>, Vec<u8>)> = transaction
        .prepare("SELECT tenant, key_gen, public_key, signature FROM kkey_keys")?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<_, _>>()?;
    for (tenant, key_gen, public_key, signature) in keys {
        let trusted = TenantId::parse(&tenant).is_ok_and(|tenant_id| {
            u64::try_from(key_gen).is_ok_and(|key_gen| {
                verify_public_key(root, &tenant_id, key_gen, &public_key, &signature).is_ok()
            })
        });
        if !trusted {
            transaction.execute(
                "DELETE FROM kkey_keys WHERE tenant = ?1 AND key_gen = ?2",
                params![tenant, key_gen],
            )?;
        }
    }

    let policies: Vec<(String, String, i64, Vec<u8>)> = transaction
        .prepare("SELECT tenant, policy, policy_version, signature FROM kkey_policies")?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<_, _>>()?;
    for (tenant, policy, version, signature) in policies {
        let trusted = TenantId::parse(&tenant).is_ok_and(|tenant_id| {
            u64::try_from(version).is_ok_and(|version| {
                verify_policy(root, &tenant_id, version, &policy, &signature).is_ok()
            })
        });
        if !trusted {
            transaction.execute("DELETE FROM kkey_policies WHERE tenant = ?1", [&tenant])?;
        }
    }
    transaction.commit()?;
    Ok(())
}

/// Per-root rollback floor (table `kkey_floors`).
#[derive(Clone, Copy)]
enum Floor {
    KeyGen,
    PolicyVersion,
}

impl Floor {
    const fn select_sql(self) -> &'static str {
        match self {
            Self::KeyGen => "SELECT key_gen FROM kkey_floors WHERE root = ?1 AND tenant = ?2",
            Self::PolicyVersion => {
                "SELECT policy_version FROM kkey_floors WHERE root = ?1 AND tenant = ?2"
            }
        }
    }

    const fn raise_sql(self) -> &'static str {
        match self {
            Self::KeyGen => {
                "INSERT INTO kkey_floors (root, tenant, key_gen) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (root, tenant) DO UPDATE SET key_gen = max(coalesce(key_gen, ?3), ?3)"
            }
            Self::PolicyVersion => {
                "INSERT INTO kkey_floors (root, tenant, policy_version) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (root, tenant) DO UPDATE \
                 SET policy_version = max(coalesce(policy_version, ?3), ?3)"
            }
        }
    }
}

fn read_floor(
    connection: &Connection,
    root: &KKeyRootKey,
    tenant: &str,
    floor: Floor,
) -> Result<Option<i64>, FileCryptoError> {
    Ok(connection
        .query_row(
            floor.select_sql(),
            params![root.as_bytes().as_slice(), tenant],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten())
}

fn raise_floor(
    connection: &Connection,
    root: &KKeyRootKey,
    tenant: &str,
    floor: Floor,
    value: i64,
) -> Result<(), FileCryptoError> {
    connection.execute(
        floor.raise_sql(),
        params![root.as_bytes().as_slice(), tenant, value],
    )?;
    Ok(())
}

pub(super) fn stored_policy(
    connection: &Connection,
    tenant: &TenantId,
) -> Result<Option<(ProfilePolicy, u64)>, FileCryptoError> {
    let stored: Option<(String, i64)> = connection
        .query_row(
            "SELECT policy, policy_version FROM kkey_policies WHERE tenant = ?1",
            [tenant.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(policy, version)| {
            Ok((
                ProfilePolicy::from_name(&policy),
                from_sql_integer(version)?,
            ))
        })
        .transpose()
}

pub(super) fn highest_public_key(
    connection: &Connection,
    tenant: &TenantId,
) -> Result<Option<(u64, KKeyElement)>, FileCryptoError> {
    let stored: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT key_gen, public_key FROM kkey_keys WHERE tenant = ?1 \
             ORDER BY key_gen DESC LIMIT 1",
            [tenant.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((key_gen, public_key)) = stored else {
        return Ok(None);
    };
    let encoded: [u8; KKEY_PUBLIC_KEY_BYTES] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| FileCryptoError::store_error())?;
    Ok(Some((
        from_sql_integer(key_gen)?,
        decode_public_key(&encoded)?,
    )))
}
