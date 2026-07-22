use thiserror::Error;

#[derive(Error, Debug)]
pub enum MfaError {
    #[cfg(feature = "seal")]
    #[error("Crypto error")]
    Crypto(#[from] orion::errors::UnknownCryptoError),
    #[error("Invalid sealed secret format")]
    InvalidSealedFormat,
    #[error("Invalid TOTP code format")]
    InvalidCodeFormat,
    #[error("Invalid secret length")]
    InvalidSecretLength,
}

pub type Result<T> = std::result::Result<T, MfaError>;
