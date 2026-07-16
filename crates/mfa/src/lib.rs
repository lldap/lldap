//! TOTP MFA helpers for LLDAP (seed generation, verification, at-rest sealing).
//!
//! Library only: no SQL, GraphQL, or auth wiring.

#![forbid(non_ascii_idents)]

mod error;
mod secret;
mod totp;
mod types;

pub use error::{MfaError, Result};
pub use secret::{
    generate_seed, open_enrollment_state, open_totp_secret, otpauth_uri, seal_enrollment_state,
    seal_totp_secret, seed_base32,
};
pub use totp::{format_code, totp_code, totp_verify};
pub use types::{
    MFA_TYPE_TOTP, SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_DIGITS, TOTP_SEED_LEN, TOTP_SKEW_STEPS,
    TOTP_STEP_SECS,
};
