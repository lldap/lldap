/// 160-bit TOTP seed length (RFC 4226 / common authenticator default).
pub const TOTP_SEED_LEN: usize = 20;
/// Digits in a TOTP code.
pub const TOTP_DIGITS: u32 = 6;
/// Time step in seconds (RFC 6238 default).
pub const TOTP_STEP_SECS: u64 = 30;
/// Allowed clock skew in steps (±1 → check three windows).
pub const TOTP_SKEW_STEPS: i64 = 1;
/// Separator between password and appended TOTP code in combined logins
/// (colon, confirmed on issue #631).
pub const TOTP_SEPARATOR: char = ':';
/// Validity of a pending TOTP enrollment, from start to code confirmation.
pub const TOTP_ENROLLMENT_TTL_SECS: u64 = 5 * 60;

/// 4-byte salt stored with each sealed blob (E2+salt).
#[cfg(feature = "seal")]
pub const SEAL_SALT_LEN: usize = 4;
/// Poly1305 tag size (ChaCha20-Poly1305).
#[cfg(feature = "seal")]
pub const SEAL_TAG_LEN: usize = 16;
/// Prefix for column-stored sealed secrets.
#[cfg(feature = "seal")]
pub const SEALED_PREFIX: &str = "v1.";
/// Expected length of a sealed column value for a 20-byte seed.
#[cfg(feature = "seal")]
pub const SEALED_BLOB_LEN: usize = 57;

/// Value stored in `mfa_type` when TOTP is enrolled.
pub const MFA_TYPE_TOTP: &str = "totp";

/// Error prefix for a replayed, already-consumed code (the login doors key on it).
pub const TOTP_CODE_ALREADY_USED: &str = "TOTP code already used";
/// Error prefix for an expired pending enrollment (the frontend keys on it).
pub const TOTP_ENROLLMENT_EXPIRED: &str = "Expired TOTP enrollment";

#[cfg(feature = "seal")]
const STORAGE_KEY_INFO: &[u8] = b"lldap-totp-storage-key-v1";
#[cfg(feature = "seal")]
const NONCE_INFO_PREFIX: &[u8] = b"lldap-totp-nonce-v1";

#[cfg(feature = "seal")]
pub(crate) fn storage_key_info() -> &'static [u8] {
    STORAGE_KEY_INFO
}

#[cfg(feature = "seal")]
pub(crate) fn build_nonce_info(user_uuid: &str, salt: &[u8]) -> Vec<u8> {
    let mut info =
        Vec::with_capacity(NONCE_INFO_PREFIX.len() + 1 + user_uuid.len() + 1 + salt.len());
    info.extend_from_slice(NONCE_INFO_PREFIX);
    info.push(0);
    info.extend_from_slice(user_uuid.as_bytes());
    info.push(0);
    info.extend_from_slice(salt);
    info
}
