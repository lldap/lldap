use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{MfaError, Result};
use crate::types::{TOTP_DIGITS, TOTP_SKEW_STEPS, TOTP_STEP_SECS};

type HmacSha1 = Hmac<Sha1>;

/// RFC 4226 HOTP truncated to [`TOTP_DIGITS`].
fn hotp(secret: &[u8], counter: u64) -> Result<u32> {
    if secret.is_empty() {
        return Err(MfaError::InvalidSecretLength);
    }
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| MfaError::InvalidSecretLength)?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let bin_code = ((u32::from(result[offset]) & 0x7f) << 24)
        | (u32::from(result[offset + 1]) << 16)
        | (u32::from(result[offset + 2]) << 8)
        | u32::from(result[offset + 3]);
    let modulus = 10u32.pow(TOTP_DIGITS);
    Ok(bin_code % modulus)
}

/// TOTP code for `unix_secs` (HMAC-SHA1, 6 digits, 30s step).
pub fn totp_code(secret: &[u8], unix_secs: u64) -> Result<u32> {
    let counter = unix_secs / TOTP_STEP_SECS;
    hotp(secret, counter)
}

/// Format a code as a zero-padded digit string.
pub fn format_code(code: u32) -> String {
    format!("{:0width$}", code, width = TOTP_DIGITS as usize)
}

fn parse_code(code: &str) -> Result<u32> {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(MfaError::InvalidCodeFormat);
    }
    code.parse().map_err(|_| MfaError::InvalidCodeFormat)
}

/// Constant-time equality for two `u32` values.
fn ct_eq_u32(a: u32, b: u32) -> bool {
    let mut v = 0u32;
    v |= a ^ b;
    v == 0
}

/// Verify a TOTP code with ±[`TOTP_SKEW_STEPS`] window tolerance.
pub fn totp_verify(secret: &[u8], code: &str, unix_secs: u64) -> Result<bool> {
    let provided = match parse_code(code) {
        Ok(c) => c,
        Err(MfaError::InvalidCodeFormat) => return Ok(false),
        Err(e) => return Err(e),
    };
    let step = unix_secs / TOTP_STEP_SECS;
    let mut ok = false;
    for delta in -TOTP_SKEW_STEPS..=TOTP_SKEW_STEPS {
        let counter = step as i64 + delta;
        if counter < 0 {
            continue;
        }
        let expected = hotp(secret, counter as u64)?;
        // Non-short-circuiting accumulate so all windows are always checked.
        ok |= ct_eq_u32(expected, provided);
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // RFC 6238 Appendix B seed (ASCII) for SHA-1 vectors.
    const RFC_SEED: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_6_digits() {
        // RFC 6238 Appendix B (SHA-1, Digit=8) reduced with % 10^6 for Digit=6.
        assert_eq!(totp_code(RFC_SEED, 59).unwrap(), 287_082); // 94287082
        assert_eq!(totp_code(RFC_SEED, 1_111_111_109).unwrap(), 81_804); // 07081804
        assert_eq!(totp_code(RFC_SEED, 1_111_111_111).unwrap(), 50_471); // 14050471
        assert_eq!(totp_code(RFC_SEED, 1_234_567_890).unwrap(), 5_924); // 89005924
        assert_eq!(totp_code(RFC_SEED, 2_000_000_000).unwrap(), 279_037); // 69279037
        assert_eq!(totp_code(RFC_SEED, 20_000_000_000).unwrap(), 353_130); // 65353130
    }

    #[test]
    fn verify_accepts_current_and_skew() {
        let t = 1_111_111_111u64;
        let code = format_code(totp_code(RFC_SEED, t).unwrap());
        assert!(totp_verify(RFC_SEED, &code, t).unwrap());
        // Same step window via skew at t ± 15s still same counter for ±1 step at boundaries.
        assert!(totp_verify(RFC_SEED, &code, t + TOTP_STEP_SECS).unwrap());
        assert!(totp_verify(RFC_SEED, &code, t - TOTP_STEP_SECS).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_and_malformed() {
        let t = 1_111_111_111u64;
        assert!(!totp_verify(RFC_SEED, "000000", t).unwrap());
        assert!(!totp_verify(RFC_SEED, "12345", t).unwrap());
        assert!(!totp_verify(RFC_SEED, "abcdef", t).unwrap());
        assert!(!totp_verify(RFC_SEED, "", t).unwrap());
    }

    #[test]
    fn format_code_zero_pads() {
        assert_eq!(format_code(42), "000042");
        assert_eq!(format_code(5801), "005801");
    }
}
