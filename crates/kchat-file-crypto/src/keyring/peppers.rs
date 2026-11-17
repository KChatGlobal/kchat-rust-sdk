//! Tenant peppers, bootstrapped by a server CAS on the commitment: the winner activates its
//! pending pepper, a loser discards it and imports the winner's. Active peppers are never deleted
//! or replaced.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{FileCryptoError, TenantId, pepper::Pepper};

use super::{FileKeyring, blob, from_sql_integer, now_unix_seconds, to_sql_integer};

const STATE_PENDING: &str = "pending";
const STATE_ACTIVE: &str = "active";

impl FileKeyring {
    /// Generates a pending pepper and returns its commitment for the host's CAS. Retrying returns
    /// the same commitment; an already active generation returns `KeyConflict`.
    pub fn generate_pepper(
        &self,
        tenant: &TenantId,
        generation: u64,
    ) -> Result<[u8; 32], FileCryptoError> {
        let generation_value = to_sql_integer(generation)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT state, commitment FROM peppers WHERE tenant = ?1 AND generation = ?2",
                params![tenant.as_str(), generation_value],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((state, commitment)) = existing {
            return if state == STATE_PENDING {
                commitment
                    .as_slice()
                    .try_into()
                    .map_err(|_| FileCryptoError::store_error())
            } else {
                Err(FileCryptoError::key_conflict())
            };
        }

        let pepper = Pepper::generate(generation)?;
        let commitment = pepper.commitment();
        insert_pepper(&transaction, tenant, &pepper, &commitment, STATE_PENDING)?;
        transaction.commit()?;
        Ok(commitment)
    }

    /// Activates a pending pepper after the host wins the CAS. Idempotent.
    pub fn activate_pepper(
        &self,
        tenant: &TenantId,
        generation: u64,
    ) -> Result<(), FileCryptoError> {
        let generation_value = to_sql_integer(generation)?;
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE peppers SET state = ?3, updated_at = ?4 \
             WHERE tenant = ?1 AND generation = ?2",
            params![
                tenant.as_str(),
                generation_value,
                STATE_ACTIVE,
                now_unix_seconds()
            ],
        )?;
        if changed == 0 {
            return Err(FileCryptoError::invalid_argument());
        }
        Ok(())
    }

    /// Discards a pending pepper after the host loses the CAS. Active peppers may already be in use
    /// and return `InvalidArgument`.
    pub fn discard_pepper(
        &self,
        tenant: &TenantId,
        generation: u64,
    ) -> Result<(), FileCryptoError> {
        let generation_value = to_sql_integer(generation)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = transaction
            .query_row(
                "SELECT state FROM peppers WHERE tenant = ?1 AND generation = ?2",
                params![tenant.as_str(), generation_value],
                |row| row.get(0),
            )
            .optional()?;
        match state.as_deref() {
            None => return Ok(()),
            Some(STATE_PENDING) => {}
            Some(_) => return Err(FileCryptoError::invalid_argument()),
        }
        transaction.execute(
            "DELETE FROM peppers WHERE tenant = ?1 AND generation = ?2",
            params![tenant.as_str(), generation_value],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Stores a received pepper as active if it matches `expected_commitment`. A pending candidate
    /// is replaced; a different active value returns `KeyConflict`.
    pub fn import_pepper(
        &self,
        tenant: &TenantId,
        generation: u64,
        pepper: &[u8],
        expected_commitment: &[u8],
    ) -> Result<(), FileCryptoError> {
        let pepper = Pepper::from_bytes(generation, pepper)?;
        let commitment = pepper.commitment();
        if commitment.as_slice() != expected_commitment {
            return Err(FileCryptoError::invalid_argument());
        }

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        store_received_pepper(&transaction, tenant, &pepper)?;
        transaction.commit()?;
        Ok(())
    }
}

/// Runs in the caller's transaction (`import_pepper`, `process_control`).
pub(super) fn store_received_pepper(
    connection: &Connection,
    tenant: &TenantId,
    pepper: &Pepper,
) -> Result<(), FileCryptoError> {
    let generation_value = to_sql_integer(pepper.generation())?;
    let commitment = pepper.commitment();
    let existing: Option<(String, Vec<u8>)> = connection
        .query_row(
            "SELECT state, commitment FROM peppers WHERE tenant = ?1 AND generation = ?2",
            params![tenant.as_str(), generation_value],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match existing {
        Some((state, stored)) if state == STATE_ACTIVE => {
            return if stored == commitment {
                Ok(())
            } else {
                Err(FileCryptoError::key_conflict())
            };
        }
        Some(_) => {
            connection.execute(
                "DELETE FROM peppers WHERE tenant = ?1 AND generation = ?2",
                params![tenant.as_str(), generation_value],
            )?;
        }
        None => {}
    }
    insert_pepper(connection, tenant, pepper, &commitment, STATE_ACTIVE)
}

fn insert_pepper(
    connection: &Connection,
    tenant: &TenantId,
    pepper: &Pepper,
    commitment: &[u8; 32],
    state: &str,
) -> Result<(), FileCryptoError> {
    connection.execute(
        "INSERT INTO peppers (tenant, generation, pepper, commitment, state, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tenant.as_str(),
            to_sql_integer(pepper.generation())?,
            pepper.as_bytes().as_slice(),
            commitment.as_slice(),
            state,
            now_unix_seconds()
        ],
    )?;
    Ok(())
}

pub(super) fn active_pepper_generation(
    connection: &Connection,
    tenant: &TenantId,
) -> Result<Option<u64>, FileCryptoError> {
    let generation: Option<i64> = connection.query_row(
        "SELECT MAX(generation) FROM peppers WHERE tenant = ?1 AND state = ?2",
        params![tenant.as_str(), STATE_ACTIVE],
        |row| row.get(0),
    )?;
    generation.map(from_sql_integer).transpose()
}

pub(super) fn active_pepper(
    connection: &Connection,
    tenant: &TenantId,
) -> Result<Option<Pepper>, FileCryptoError> {
    read_active_pepper(
        connection,
        "SELECT generation, pepper FROM peppers WHERE tenant = ?1 AND state = ?2 \
         ORDER BY generation DESC LIMIT 1",
        params![tenant.as_str(), STATE_ACTIVE],
    )
}

/// Pending peppers are never returned: they cannot be used before winning the CAS.
pub(super) fn active_pepper_at(
    connection: &Connection,
    tenant: &TenantId,
    generation: u64,
) -> Result<Option<Pepper>, FileCryptoError> {
    read_active_pepper(
        connection,
        "SELECT generation, pepper FROM peppers WHERE tenant = ?1 AND state = ?2 \
         AND generation = ?3",
        params![tenant.as_str(), STATE_ACTIVE, to_sql_integer(generation)?],
    )
}

fn read_active_pepper(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> Result<Option<Pepper>, FileCryptoError> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(parameters)?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let generation = from_sql_integer(row.get(0)?)?;
    Pepper::from_bytes(generation, blob(row, 1)?)
        .map(Some)
        .map_err(|_| FileCryptoError::store_error())
}
