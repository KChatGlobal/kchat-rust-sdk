use crate::BackupError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupAccountId([u8; 16]);

impl BackupAccountId {
    pub fn parse(value: &str) -> Result<Self, BackupError> {
        let uuid = uuid::Uuid::parse_str(value).map_err(|_| BackupError::invalid_argument())?;
        Ok(Self(*uuid.as_bytes()))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for BackupAccountId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupAccountId(REDACTED)")
    }
}
