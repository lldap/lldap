use data_encoding::BASE32_NOPAD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::error::{MfaError, Result};
use crate::types::{TOTP_DIGITS, TOTP_STEP_SECS};

/// otpauth label/query escaping: RFC 3986 unreserved characters pass through.
const OTPAUTH_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Base32 (no padding) encoding used by authenticator apps.
pub fn seed_base32(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// Decode an authenticator-style base32 secret (mirror of [`seed_base32`]).
pub fn seed_from_base32(secret: &str) -> Result<Vec<u8>> {
    BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|_| MfaError::InvalidBase32)
}

/// Build a standard `otpauth://totp/...` URI (SHA1, 6 digits, 30s).
pub fn otpauth_uri(issuer: &str, account_name: &str, secret_base32: &str) -> String {
    // Label is issuer:account; query repeats issuer for Google Authenticator compatibility.
    let label = format!(
        "{}:{}",
        utf8_percent_encode(issuer, OTPAUTH_SET),
        utf8_percent_encode(account_name, OTPAUTH_SET)
    );
    format!(
        "otpauth://totp/{label}?secret={secret_base32}&issuer={issuer_q}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECS}",
        issuer_q = utf8_percent_encode(issuer, OTPAUTH_SET),
    )
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
        assert!(matches!(
            seed_from_base32("not base32!"),
            Err(MfaError::InvalidBase32)
        ));
        let uri = otpauth_uri("LLDAP", "alice@example.com", &b32);
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("algorithm=SHA1"));
        // Reserved characters in the label parts are percent-encoded.
        let uri = otpauth_uri("My Org", "bob:smith?", &b32);
        assert!(uri.contains("otpauth://totp/My%20Org:bob%3Asmith%3F?secret="));
        assert!(uri.contains("issuer=My%20Org&"));
    }
}
