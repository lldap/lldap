//! TOTP MFA helpers for LLDAP (seed generation, verification, at-rest sealing).
//!
//! Library only: no SQL, GraphQL, or auth wiring. The default `seal` feature
//! carries the at-rest sealing; without it the crate is wasm-friendly TOTP
//! math and encodings for the frontend.

#![forbid(non_ascii_idents)]

mod encoding;
mod error;
#[cfg(feature = "seal")]
mod secret;
mod totp;
mod types;
#[cfg(feature = "seal")]
mod used_codes;

pub use encoding::{otpauth_uri, seed_base32, seed_from_base32};
pub use error::{MfaError, Result};
#[cfg(feature = "seal")]
pub use secret::{
    EnrollmentState, generate_seed, open_enrollment, open_totp_secret, seal_enrollment,
    seal_totp_secret,
};
pub use totp::{format_code, split_totp_suffix, totp_code, totp_verify};
#[cfg(feature = "seal")]
pub use types::{SEALED_BLOB_LEN, SEALED_PREFIX};
pub use types::{
    TOTP_CODE_ALREADY_USED, TOTP_ENROLLMENT_EXPIRED, TOTP_ENROLLMENT_TTL_SECS, TOTP_SEED_LEN,
    TOTP_SEPARATOR,
};
#[cfg(feature = "seal")]
pub use used_codes::UsedCodes;
