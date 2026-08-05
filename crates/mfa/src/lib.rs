//! TOTP helpers and (optional) at-rest sealing for LLDAP.

#![forbid(non_ascii_idents)]

mod encoding;
mod error;
#[cfg(feature = "seal")]
mod failed_attempts;
#[cfg(feature = "seal")]
mod secret;
mod totp;
mod types;
#[cfg(feature = "seal")]
mod used_codes;

pub use encoding::{otpauth_uri, seed_base32, seed_from_base32};
pub use error::{MfaError, Result};
#[cfg(feature = "seal")]
pub use failed_attempts::FailedAttempts;
#[cfg(feature = "seal")]
pub use secret::{
    EnrollmentState, generate_seed, open_enrollment, open_totp_secret, seal_enrollment,
    seal_totp_secret,
};
pub use totp::{format_code, split_totp_suffix, totp_code, totp_verify};
#[cfg(feature = "seal")]
pub use types::{SEALED_BLOB_LEN, SEALED_PREFIX};
pub use types::{
    TOTP_CODE_ALREADY_USED, TOTP_CURRENT_CODE_REQUIRED, TOTP_DIGITS, TOTP_ENROLLMENT_EXPIRED,
    TOTP_ENROLLMENT_TTL_SECS, TOTP_SEED_LEN, TOTP_SEPARATOR, TOTP_TOO_MANY_ATTEMPTS,
};
#[cfg(feature = "seal")]
pub use used_codes::UsedCodes;
