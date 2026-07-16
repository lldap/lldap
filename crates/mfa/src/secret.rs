use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use data_encoding::BASE32_NOPAD;
use orion::aead;
use orion::hazardous::aead::chacha20poly1305::{self, Nonce, SecretKey};
use orion::hazardous::kdf::hkdf;
use rand::RngCore;

use crate::error::{MfaError, Result};
use crate::types::{
    SEAL_SALT_LEN, SEAL_TAG_LEN, SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_DIGITS, TOTP_SEED_LEN,
    TOTP_STEP_SECS, build_nonce_info, storage_key_info,
};

/// Generate a 160-bit TOTP seed.
pub fn generate_seed() -> [u8; TOTP_SEED_LEN] {
    let mut seed = [0u8; TOTP_SEED_LEN];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

/// Base32 (no padding) encoding used by authenticator apps.
pub fn seed_base32(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
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

fn derive_storage_key(ikm: &[u8]) -> Result<SecretKey> {
    let mut key_bytes = [0u8; 32];
    hkdf::sha256::derive_key(&[], ikm, Some(storage_key_info()), &mut key_bytes)?;
    Ok(SecretKey::from_slice(&key_bytes)?)
}

fn derive_nonce(ikm: &[u8], user_uuid: &str, salt: &[u8]) -> Result<Nonce> {
    let info = build_nonce_info(user_uuid, salt);
    let mut out = [0u8; 32];
    hkdf::sha256::derive_key(&[], ikm, Some(&info), &mut out)?;
    Ok(Nonce::from_slice(&out[..12])?)
}

fn aad(user_uuid: &str, salt: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(user_uuid.len() + salt.len());
    a.extend_from_slice(user_uuid.as_bytes());
    a.extend_from_slice(salt);
    a
}

/// Seal a TOTP seed for the `totp_secret` column (E2+salt, ≤64 chars).
pub fn seal_totp_secret(ikm: &[u8], user_uuid: &str, seed: &[u8]) -> Result<String> {
    if seed.len() != TOTP_SEED_LEN {
        return Err(MfaError::InvalidSecretLength);
    }
    let storage_key = derive_storage_key(ikm)?;
    let mut salt = [0u8; SEAL_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let nonce = derive_nonce(ikm, user_uuid, &salt)?;
    let ad = aad(user_uuid, &salt);

    let mut ct_and_tag = vec![0u8; seed.len() + SEAL_TAG_LEN];
    chacha20poly1305::seal(&storage_key, &nonce, seed, Some(&ad), &mut ct_and_tag)?;

    let mut packed = Vec::with_capacity(SEAL_SALT_LEN + ct_and_tag.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&ct_and_tag);
    let encoded = URL_SAFE_NO_PAD.encode(&packed);
    let sealed = format!("{SEALED_PREFIX}{encoded}");
    debug_assert_eq!(sealed.len(), SEALED_BLOB_LEN);
    Ok(sealed)
}

/// Open a column-stored sealed TOTP seed.
pub fn open_totp_secret(ikm: &[u8], user_uuid: &str, sealed: &str) -> Result<Vec<u8>> {
    let rest = sealed
        .strip_prefix(SEALED_PREFIX)
        .ok_or(MfaError::InvalidSealedFormat)?;
    let packed = URL_SAFE_NO_PAD
        .decode(rest.as_bytes())
        .map_err(|_| MfaError::InvalidSealedFormat)?;
    if packed.len() < SEAL_SALT_LEN + SEAL_TAG_LEN + 1 {
        return Err(MfaError::InvalidSealedFormat);
    }
    let (salt, ct_and_tag) = packed.split_at(SEAL_SALT_LEN);
    let storage_key = derive_storage_key(ikm)?;
    let nonce = derive_nonce(ikm, user_uuid, salt)?;
    let ad = aad(user_uuid, salt);

    let mut plain = vec![0u8; ct_and_tag.len() - SEAL_TAG_LEN];
    chacha20poly1305::open(&storage_key, &nonce, ct_and_tag, Some(&ad), &mut plain)
        .map_err(MfaError::from)?;
    Ok(plain)
}

/// Seal enrollment pending state for the wire (high-level AEAD; not column-sized).
pub fn seal_enrollment_state(server_key: &[u8], state: &[u8]) -> Result<Vec<u8>> {
    let key = aead::SecretKey::from_slice(server_key)?;
    Ok(aead::seal(&key, state)?)
}

/// Open enrollment pending state.
pub fn open_enrollment_state(server_key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let key = aead::SecretKey::from_slice(server_key)?;
    Ok(aead::open(&key, blob)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SEALED_BLOB_LEN;
    use pretty_assertions::assert_eq;

    const IKM: &[u8] = b"0123456789abcdef0123456789abcdef"; // 32 bytes
    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn generate_seed_length() {
        let s = generate_seed();
        assert_eq!(s.len(), TOTP_SEED_LEN);
        assert_ne!(s, [0u8; TOTP_SEED_LEN]);
    }

    #[test]
    fn base32_and_otpauth() {
        let seed = b"12345678901234567890";
        let b32 = seed_base32(seed);
        assert!(!b32.contains('='));
        let uri = otpauth_uri("LLDAP", "alice@example.com", &b32);
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("algorithm=SHA1"));
    }

    #[test]
    fn seal_open_round_trip() {
        let seed = generate_seed();
        let sealed = seal_totp_secret(IKM, UUID, &seed).unwrap();
        assert_eq!(sealed.len(), SEALED_BLOB_LEN);
        assert!(sealed.starts_with("v1."));
        let opened = open_totp_secret(IKM, UUID, &sealed).unwrap();
        assert_eq!(opened, seed);
    }

    #[test]
    fn seal_length_and_grammar() {
        let seed = [7u8; TOTP_SEED_LEN];
        let sealed = seal_totp_secret(IKM, UUID, &seed).unwrap();
        assert_eq!(sealed.len(), 57);
        let rest = sealed.strip_prefix("v1.").unwrap();
        assert_eq!(rest.len(), 54);
        assert!(
            rest.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn wrong_ikm_fails() {
        let seed = generate_seed();
        let sealed = seal_totp_secret(IKM, UUID, &seed).unwrap();
        let bad_ikm = b"ff23456789abcdef0123456789abcdef";
        assert!(open_totp_secret(bad_ikm, UUID, &sealed).is_err());
    }

    #[test]
    fn wrong_uuid_fails() {
        let seed = generate_seed();
        let sealed = seal_totp_secret(IKM, UUID, &seed).unwrap();
        assert!(open_totp_secret(IKM, "other-uuid", &sealed).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let seed = generate_seed();
        let sealed = seal_totp_secret(IKM, UUID, &seed).unwrap();
        let mut bytes = sealed.into_bytes();
        let i = bytes.len() - 2;
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        let sealed = String::from_utf8(bytes).unwrap();
        assert!(open_totp_secret(IKM, UUID, &sealed).is_err());
    }

    #[test]
    fn different_uuid_different_ciphertext() {
        let seed = [9u8; TOTP_SEED_LEN];
        let a = seal_totp_secret(IKM, "uuid-a", &seed).unwrap();
        let b = seal_totp_secret(IKM, "uuid-b", &seed).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_each_seal() {
        let seed = [3u8; TOTP_SEED_LEN];
        let a = seal_totp_secret(IKM, UUID, &seed).unwrap();
        let b = seal_totp_secret(IKM, UUID, &seed).unwrap();
        assert_ne!(a, b);
        assert_eq!(open_totp_secret(IKM, UUID, &a).unwrap(), seed);
        assert_eq!(open_totp_secret(IKM, UUID, &b).unwrap(), seed);
    }

    #[test]
    fn bad_prefix() {
        assert!(matches!(
            open_totp_secret(IKM, UUID, "v0.abc"),
            Err(MfaError::InvalidSealedFormat)
        ));
        assert!(matches!(
            open_totp_secret(IKM, UUID, "not-sealed"),
            Err(MfaError::InvalidSealedFormat)
        ));
    }

    #[test]
    fn enrollment_state_round_trip() {
        let key = b"0123456789abcdef0123456789abcdef";
        let state = b"pending-enrollment-payload";
        let blob = seal_enrollment_state(key, state).unwrap();
        assert_ne!(blob.as_slice(), state.as_slice());
        assert_eq!(open_enrollment_state(key, &blob).unwrap(), state);
    }
}
