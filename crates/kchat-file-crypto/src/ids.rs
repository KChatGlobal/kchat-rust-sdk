use crate::FileCryptoError;

/// Maximum UTF-8 byte length of server- or host-issued IDs.
pub const MAX_ID_BYTES: usize = 256;

pub(crate) fn validate_id(value: &str) -> Result<(), FileCryptoError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES {
        return Err(FileCryptoError::invalid_argument());
    }
    Ok(())
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TenantId(String);

impl TenantId {
    pub fn parse(value: &str) -> Result<Self, FileCryptoError> {
        validate_id(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for TenantId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TenantId(REDACTED)")
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OperationId(String);

impl OperationId {
    pub fn parse(value: &str) -> Result<Self, FileCryptoError> {
        validate_id(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for OperationId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OperationId(REDACTED)")
    }
}
