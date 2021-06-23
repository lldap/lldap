use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Authentication error for `{0}`")]
    AuthenticationError(String),
    #[error("Database error: `{0}`")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Authentication protocol error for `{0}`")]
    AuthenticationProtocolError(#[from] lldap_model::opaque::AuthenticationError),
    #[error("Internal error: `{0}`")]
    InternalError(String),
}

pub type Result<T> = std::result::Result<T, DomainError>;
