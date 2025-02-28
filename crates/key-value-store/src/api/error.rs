use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyValueError {
    #[error("Storage error: `{0}`")]
    StorageError(String),
    #[error("Unable to decode value: `{0}`")]
    DecodingError(String),
}

#[cfg(feature = "seaorm")]
impl From<sea_orm::DbErr> for KeyValueError {
    fn from(value: sea_orm::DbErr) -> Self {
        KeyValueError::StorageError(value.to_string())
    }
}

#[cfg(feature = "seaorm")]
impl From<sea_orm::TransactionError<KeyValueError>> for KeyValueError {
    fn from(value: sea_orm::TransactionError<KeyValueError>) -> Self {
        match value {
            sea_orm::TransactionError::Connection(e) => e.into(),
            sea_orm::TransactionError::Transaction(e) => e,
        }
    }
}
