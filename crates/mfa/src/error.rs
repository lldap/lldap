use thiserror::Error;

#[derive(Error, Debug)]
pub enum MfaError {
    #[cfg(feature = "seal")]
    #[error("Crypto error")]
    Crypto(#[from] orion::errors::UnknownCryptoError),
    #[error("Invalid sealed secret format")]
    InvalidSealedFormat,
    #[cfg(feature = "seal")]
    #[error("{}", crate::types::TOTP_ENROLLMENT_EXPIRED)]
    EnrollmentExpired,
    #[cfg(feature = "seal")]
    #[error("Serialization error")]
    Serialization(#[from] bincode::Error),
    #[error("Invalid TOTP code format")]
    InvalidCodeFormat,
    #[error("Invalid secret length")]
    InvalidSecretLength,
    #[error("Invalid base32 encoding")]
    InvalidBase32,
}

pub type Result<T> = std::result::Result<T, MfaError>;
