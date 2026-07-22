use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use orion::aead;
use orion::hazardous::aead::chacha20poly1305::{self, Nonce, SecretKey};
use orion::hazardous::kdf::hkdf;
use rand::RngCore;

use crate::error::{MfaError, Result};
use crate::types::{
    SEAL_SALT_LEN, SEAL_TAG_LEN, SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_SEED_LEN, build_nonce_info,
    storage_key_info,
};

/// Generate a 160-bit TOTP seed.
pub fn generate_seed() -> [u8; TOTP_SEED_LEN] {
    let mut seed = [0u8; TOTP_SEED_LEN];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
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
    rand::rngs::OsRng.fill_bytes(&mut salt);
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
    if packed.len() != SEAL_SALT_LEN + TOTP_SEED_LEN + SEAL_TAG_LEN {
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
    fn wrong_packed_length_fails() {
        let short = format!("{SEALED_PREFIX}{}", URL_SAFE_NO_PAD.encode([0u8; 30]));
        assert!(matches!(
            open_totp_secret(IKM, UUID, &short),
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
