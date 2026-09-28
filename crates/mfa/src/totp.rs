use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{MfaError, Result};
use crate::types::{TOTP_DIGITS, TOTP_SEPARATOR, TOTP_SKEW_STEPS, TOTP_STEP_SECS};

type HmacSha1 = Hmac<Sha1>;

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

pub fn totp_code(secret: &[u8], unix_secs: u64) -> Result<u32> {
    let counter = unix_secs / TOTP_STEP_SECS;
    hotp(secret, counter)
}

pub fn format_code(code: u32) -> String {
    format!("{:0width$}", code, width = TOTP_DIGITS as usize)
}

fn parse_code(code: &str) -> Option<u32> {
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}

// Optimizer barrier so windows are not short-circuited. black_box is not constant-time;
// the surrounding HMAC dominates.
fn barrier_eq_u32(a: u32, b: u32) -> bool {
    std::hint::black_box(a ^ b) == 0
}

pub fn split_totp_suffix(password: &str) -> Option<(&str, &str)> {
    let (prefix, code) = password.rsplit_once(TOTP_SEPARATOR)?;
    (code.len() == TOTP_DIGITS as usize && code.bytes().all(|b| b.is_ascii_digit()))
        .then_some((prefix, code))
}

pub fn totp_verify(secret: &[u8], code: &str, unix_secs: u64) -> Result<bool> {
    let Some(provided) = parse_code(code) else {
        return Ok(false);
    };
    let step = unix_secs / TOTP_STEP_SECS;
    let mut ok = false;
    for delta in -TOTP_SKEW_STEPS..=TOTP_SKEW_STEPS {
        let counter = step as i64 + delta;
        if counter < 0 {
            continue;
        }
        let expected = hotp(secret, counter as u64)?;
        ok |= barrier_eq_u32(expected, provided);
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // RFC 6238 Appendix B seed (ASCII); expected codes are Digit=8 vectors % 10^6.
    const RFC_SEED: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_6_digits() {
        assert_eq!(totp_code(RFC_SEED, 59).unwrap(), 287_082); // 94287082
        assert_eq!(totp_code(RFC_SEED, 1_111_111_109).unwrap(), 81_804); // 07081804
        assert_eq!(totp_code(RFC_SEED, 1_111_111_111).unwrap(), 50_471); // 14050471
        assert_eq!(totp_code(RFC_SEED, 1_234_567_890).unwrap(), 5_924); // 89005924
        assert_eq!(totp_code(RFC_SEED, 2_000_000_000).unwrap(), 279_037); // 69279037
        assert_eq!(totp_code(RFC_SEED, 20_000_000_000).unwrap(), 353_130); // 65353130
    }

    #[test]
    fn verify_accepts_skew_and_rejects_the_rest() {
        let t = 1_111_111_111u64;
        let code = format_code(totp_code(RFC_SEED, t).unwrap());
        assert_eq!(format_code(42), "000042");
        assert!(totp_verify(RFC_SEED, &code, t).unwrap());
        assert!(totp_verify(RFC_SEED, &code, t + TOTP_STEP_SECS).unwrap());
        assert!(totp_verify(RFC_SEED, &code, t - TOTP_STEP_SECS).unwrap());
        assert!(!totp_verify(RFC_SEED, &code, t + 2 * TOTP_STEP_SECS).unwrap());
        assert!(!totp_verify(RFC_SEED, "000000", t).unwrap());
        assert!(!totp_verify(RFC_SEED, "12345", t).unwrap());
        assert!(!totp_verify(RFC_SEED, "abcdef", t).unwrap());
        assert!(!totp_verify(RFC_SEED, "", t).unwrap());
        assert!(!totp_verify(RFC_SEED, &format!(" {code}"), t).unwrap());
        assert!(!totp_verify(RFC_SEED, &format!("{code} "), t).unwrap());
        assert!(matches!(
            totp_code(&[], t),
            Err(MfaError::InvalidSecretLength)
        ));
    }

    #[test]
    fn split_totp_suffix_cases() {
        assert_eq!(
            split_totp_suffix("pass:word:123456"),
            Some(("pass:word", "123456"))
        );
        assert_eq!(split_totp_suffix(":123456"), Some(("", "123456")));
        assert_eq!(split_totp_suffix("password"), None);
        assert_eq!(split_totp_suffix("password:12345"), None);
        assert_eq!(split_totp_suffix("password:1234567"), None);
        assert_eq!(split_totp_suffix("password:12345a"), None);
    }
}
