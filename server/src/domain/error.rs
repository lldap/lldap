use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Authentication error: `{0}`")]
    AuthenticationError(String),
    #[error("Database error: `{0}`")]
    DatabaseError(#[from] sea_orm::DbErr),
    #[error("Database transaction error: `{0}`")]
    DatabaseTransactionError(#[from] sea_orm::TransactionError<sea_orm::DbErr>),
    #[error("Authentication protocol error for `{0}`")]
    AuthenticationProtocolError(#[from] lldap_auth::opaque::AuthenticationError),
    #[error("Unknown crypto error: `{0}`")]
    UnknownCryptoError(#[from] orion::errors::UnknownCryptoError),
    #[error("Binary serialization error: `{0}`")]
    BinarySerializationError(#[from] bincode::Error),
    #[error("Invalid base64: `{0}`")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Entity not found: `{0}`")]
    EntityNotFound(String),
    #[error("Internal error: `{0}`")]
    InternalError(String),
}

impl From<sea_orm::TransactionError<DomainError>> for DomainError {
    fn from(value: sea_orm::TransactionError<DomainError>) -> Self {
        match value {
            sea_orm::TransactionError::Connection(e) => e.into(),
            sea_orm::TransactionError::Transaction(e) => e,
        }
    }
}

pub type Result<T> = std::result::Result<T, DomainError>;
