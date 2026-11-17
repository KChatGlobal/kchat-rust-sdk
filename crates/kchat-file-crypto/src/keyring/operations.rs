//! Content plans persisted per operation id. A plan is immutable: planning an operation again
//! returns the stored plan, so retries yield the same bytes even after key rotation. Reusing an id
//! for other content returns `OperationConflict`.

use std::collections::HashSet;

use rusqlite::{Connection, TransactionBehavior, params};

use crate::{
    ContentHash, ContentPlan, ContentProfile, FileCryptoError, MAX_OPRF_BATCH_SIZE, OperationId,
    OprfRequest, OprfResponse, OprfSession, ProfilePolicy, RandomPlanReason, TenantId,
    profile::ContentKeyMaterial,
};

use super::{
    FileKeyring, blob, from_sql_integer,
    key_config::{highest_public_key, stored_policy},
    now_unix_seconds,
    peppers::active_pepper,
    to_sql_integer,
};

const CONTENT_OPERATION_KIND: &str = "content";

impl FileKeyring {
    /// Blinds up to [`MAX_OPRF_BATCH_SIZE`] contents for one `Evaluate` call, using the highest
    /// verified public key and active pepper. Requires a `Hybrid` policy; writes nothing.
    pub fn begin_oprf(
        &self,
        tenant: &TenantId,
        contents: &[&ContentHash],
    ) -> Result<(OprfSession, OprfRequest), FileCryptoError> {
        if contents.is_empty() {
            return Err(FileCryptoError::invalid_argument());
        }
        if contents.len() > MAX_OPRF_BATCH_SIZE {
            return Err(FileCryptoError::resource_limit_exceeded());
        }
        // A duplicated operation would produce two plans for one id.
        let mut operation_ids = HashSet::with_capacity(contents.len());
        if !contents
            .iter()
            .all(|content| operation_ids.insert(content.operation_id()))
        {
            return Err(FileCryptoError::invalid_argument());
        }

        let (key_gen, public_key, pepper) = {
            let connection = self.lock()?;
            require_hybrid_policy(&connection, tenant)?;
            let (key_gen, public_key) = highest_public_key(&connection, tenant)?
                .ok_or_else(FileCryptoError::key_config_required)?;
            let pepper =
                active_pepper(&connection, tenant)?.ok_or_else(FileCryptoError::pepper_required)?;
            (key_gen, public_key, pepper)
        };
        OprfSession::begin(tenant, key_gen, public_key, pepper, contents)
    }

    /// Verifies the response and stores one hybrid plan per content, in request order, in one
    /// transaction. Existing plans are kept; an `OperationConflict` rolls back the whole batch.
    /// Nothing is stored if the policy stopped being `Hybrid` since `begin_oprf`.
    pub fn finish_oprf(
        &self,
        session: OprfSession,
        response: &OprfResponse,
    ) -> Result<Vec<ContentPlan>, FileCryptoError> {
        let plans = session.finish(response)?;
        let tenant = session.tenant().clone();
        // Zeroize the blinds and pepper before waiting for the store lock.
        drop(session);

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_hybrid_policy(&transaction, &tenant)?;
        let plans = plans
            .into_iter()
            .map(|plan| store_or_existing(&transaction, Some(&tenant), plan))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit()?;
        Ok(plans)
    }

    /// Creates and stores a `random-dek/v1` plan, or returns the operation's existing plan. Never
    /// use it after `ACCESS_DENIED` or an invalid proof or signature: abort the upload instead.
    pub fn plan_random(
        &self,
        content: &ContentHash,
        reason: RandomPlanReason,
    ) -> Result<ContentPlan, FileCryptoError> {
        let plan = ContentPlan::new(
            ContentProfile::RandomDekV1,
            ContentKeyMaterial::random()?,
            content.duplicate(),
            Some(reason),
        );
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let plan = store_or_existing(&transaction, None, plan)?;
        transaction.commit()?;
        Ok(plan)
    }

    /// Stored plan for `content`'s operation, so a resumed upload needs no key service.
    pub fn prepared_plan(
        &self,
        content: &ContentHash,
    ) -> Result<Option<ContentPlan>, FileCryptoError> {
        let connection = self.lock()?;
        load_plan(&connection, None, content)
    }

    /// Deletes the operation's plan (it holds the DEK) once the descriptor is committed or the
    /// operation is abandoned.
    pub fn forget_operation(&self, operation_id: &OperationId) -> Result<(), FileCryptoError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM prepared_ops WHERE operation_id = ?1",
            [operation_id.as_str()],
        )?;
        Ok(())
    }
}

fn require_hybrid_policy(
    connection: &Connection,
    tenant: &TenantId,
) -> Result<(), FileCryptoError> {
    match stored_policy(connection, tenant)? {
        None => Err(FileCryptoError::key_config_required()),
        Some((ProfilePolicy::Random, _)) => Err(FileCryptoError::profile_not_allowed()),
        Some((ProfilePolicy::Hybrid, _)) => Ok(()),
    }
}

/// `tenant` is the hybrid plan's tenant (`None` for random plans).
fn store_or_existing(
    connection: &Connection,
    tenant: Option<&TenantId>,
    plan: ContentPlan,
) -> Result<ContentPlan, FileCryptoError> {
    if let Some(existing) = load_plan(connection, tenant, plan.content())? {
        return Ok(existing);
    }
    let (key_gen, pepper_gen) = plan.profile().generations();
    let (key_gen, pepper_gen) = (
        key_gen.map(to_sql_integer).transpose()?,
        pepper_gen.map(to_sql_integer).transpose()?,
    );
    let content = plan.content();
    connection.execute(
        "INSERT INTO prepared_ops (operation_id, kind, plaintext_sha256, plaintext_len, profile, \
         tenant, key_gen, pepper_gen, dek, nonce_prefix, random_reason, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            content.operation_id().as_str(),
            CONTENT_OPERATION_KIND,
            content.plaintext_sha256().as_slice(),
            to_sql_integer(content.plaintext_len())?,
            plan.profile().id(),
            tenant.map(TenantId::as_str),
            key_gen,
            pepper_gen,
            plan.material().dek.as_slice(),
            plan.material().nonce_prefix.as_slice(),
            plan.random_reason().map(|reason| reason.as_str()),
            now_unix_seconds()
        ],
    )?;
    Ok(plan)
}

/// Stored plan for `content`'s operation. A different content, or a hybrid plan derived for another
/// tenant than `tenant` (when given), returns `OperationConflict`.
fn load_plan(
    connection: &Connection,
    tenant: Option<&TenantId>,
    content: &ContentHash,
) -> Result<Option<ContentPlan>, FileCryptoError> {
    let mut statement = connection.prepare(
        "SELECT plaintext_sha256, plaintext_len, profile, key_gen, pepper_gen, dek, \
         nonce_prefix, random_reason, tenant FROM prepared_ops \
         WHERE operation_id = ?1 AND kind = ?2",
    )?;
    let mut rows = statement.query(params![
        content.operation_id().as_str(),
        CONTENT_OPERATION_KIND
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };

    let plaintext_sha256: [u8; 32] = blob(row, 0)?
        .try_into()
        .map_err(|_| FileCryptoError::store_error())?;
    let plaintext_len = from_sql_integer(row.get(1)?)?;
    if plaintext_len != content.plaintext_len() || plaintext_sha256 != *content.plaintext_sha256() {
        return Err(FileCryptoError::operation_conflict());
    }
    let stored_tenant: Option<String> = row.get(8)?;
    if let (Some(tenant), Some(stored)) = (tenant, stored_tenant.as_deref())
        && tenant.as_str() != stored
    {
        return Err(FileCryptoError::operation_conflict());
    }

    let profile_id: String = row.get(2)?;
    let key_gen: Option<i64> = row.get(3)?;
    let pepper_gen: Option<i64> = row.get(4)?;
    // An unknown profile (newer SDK) stays `UnsupportedProfile`; other mismatches are corruption.
    let profile = ContentProfile::from_parts(
        &profile_id,
        key_gen.map(from_sql_integer).transpose()?,
        pepper_gen.map(from_sql_integer).transpose()?,
        FileCryptoError::store_error,
    )?;
    let material = ContentKeyMaterial::from_slices(blob(row, 5)?, blob(row, 6)?)?;
    let random_reason = row
        .get::<_, Option<String>>(7)?
        .map(|reason| RandomPlanReason::parse(&reason))
        .transpose()?;
    Ok(Some(ContentPlan::new(
        profile,
        material,
        content.duplicate(),
        random_reason,
    )))
}
