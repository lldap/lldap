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

pub use encoding::{otpauth_uri, seed_base32, seed_from_base32};
pub use error::{MfaError, Result};
#[cfg(feature = "seal")]
pub use secret::{
    generate_seed, open_enrollment_state, open_totp_secret, seal_enrollment_state, seal_totp_secret,
};
pub use totp::{format_code, split_totp_suffix, totp_code, totp_verify};
pub use types::{
    MFA_TYPE_TOTP, TOTP_CODE_ALREADY_USED, TOTP_DIGITS, TOTP_ENROLLMENT_EXPIRED,
    TOTP_ENROLLMENT_TTL_SECS, TOTP_SEED_LEN, TOTP_SEPARATOR, TOTP_SKEW_STEPS, TOTP_STEP_SECS,
};
#[cfg(feature = "seal")]
pub use types::{SEALED_BLOB_LEN, SEALED_PREFIX};
