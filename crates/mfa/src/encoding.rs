use data_encoding::BASE32_NOPAD;

use crate::error::{MfaError, Result};
use crate::types::{TOTP_DIGITS, TOTP_STEP_SECS};

/// Base32 (no padding) encoding used by authenticator apps.
pub fn seed_base32(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// Decode an authenticator-style base32 secret (mirror of [`seed_base32`]).
pub fn seed_from_base32(secret: &str) -> Result<Vec<u8>> {
    BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|_| MfaError::InvalidSecretLength)
}

/// Build a standard `otpauth://totp/...` URI (SHA1, 6 digits, 30s).
pub fn otpauth_uri(issuer: &str, account_name: &str, secret_base32: &str) -> String {
    // Label is issuer:account; query repeats issuer for Google Authenticator compatibility.
    let label = format!(
        "{}:{}",
        urlencoding_minimal(issuer),
        urlencoding_minimal(account_name)
    );
    format!(
        "otpauth://totp/{label}?secret={secret_base32}&issuer={issuer_q}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECS}",
        issuer_q = urlencoding_minimal(issuer),
    )
}

/// Minimal URL-encoding for otpauth labels (encode reserved characters).
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn base32_and_otpauth() {
        let seed = b"12345678901234567890";
        let b32 = seed_base32(seed);
        assert!(!b32.contains('='));
        assert_eq!(seed_from_base32(&b32).unwrap(), seed);
        assert!(seed_from_base32("not base32!").is_err());
        let uri = otpauth_uri("LLDAP", "alice@example.com", &b32);
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("algorithm=SHA1"));
    }
}
