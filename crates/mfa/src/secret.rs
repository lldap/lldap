use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use orion::aead;
use orion::hazardous::aead::chacha20poly1305::{self, Nonce, SecretKey};
use orion::hazardous::kdf::hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{MfaError, Result};
use crate::types::{
    SEAL_SALT_LEN, SEAL_TAG_LEN, SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_ENROLLMENT_TTL_SECS,
    TOTP_SEED_LEN, build_nonce_info, enrollment_key_info, storage_key_info,
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

// Distinct info string: wire-state blobs must never share a key with column blobs.
fn derive_enrollment_key(ikm: &[u8]) -> Result<aead::SecretKey> {
    let mut key_bytes = [0u8; 32];
    hkdf::sha256::derive_key(&[], ikm, Some(enrollment_key_info()), &mut key_bytes)?;
    Ok(aead::SecretKey::from_slice(&key_bytes)?)
}

/// A TOTP enrollment awaiting confirmation, sealed until the code is verified.
/// The caller owns the user comparison: `user_id` here is a plain string.
#[derive(Serialize, Deserialize)]
pub struct EnrollmentState {
    // Discriminates the sealed blob: bincode ignores trailing bytes, so an
    // unrelated payload could otherwise be parsed as an enrollment.
    kind: u8,
    pub user_id: String,
    pub seed: [u8; TOTP_SEED_LEN],
    expiry_unix: i64,
}

const STATE_KIND_ENROLLMENT: u8 = 1;

/// Seal a pending enrollment, valid for [`TOTP_ENROLLMENT_TTL_SECS`].
pub fn seal_enrollment(
    ikm: &[u8],
    user_id: &str,
    seed: &[u8; TOTP_SEED_LEN],
    now_unix: i64,
) -> Result<String> {
    let state = EnrollmentState {
        kind: STATE_KIND_ENROLLMENT,
        user_id: user_id.to_owned(),
        seed: *seed,
        expiry_unix: now_unix + TOTP_ENROLLMENT_TTL_SECS as i64,
    };
    let key = derive_enrollment_key(ikm)?;
    let sealed = aead::seal(&key, &bincode::serialize(&state)?)?;
    Ok(URL_SAFE_NO_PAD.encode(sealed))
}

/// Open a pending enrollment, rejecting anything expired or malformed.
pub fn open_enrollment(ikm: &[u8], sealed: &str, now_unix: i64) -> Result<EnrollmentState> {
    let key = derive_enrollment_key(ikm)?;
    let blob = URL_SAFE_NO_PAD
        .decode(sealed.as_bytes())
        .map_err(|_| MfaError::InvalidSealedFormat)?;
    let state: EnrollmentState = bincode::deserialize(&aead::open(&key, &blob)?)?;
    if state.kind != STATE_KIND_ENROLLMENT {
        return Err(MfaError::InvalidSealedFormat);
    }
    if state.expiry_unix < now_unix {
        return Err(MfaError::EnrollmentExpired);
    }
    Ok(state)
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
    fn enrollment_round_trip() {
        let seed = generate_seed();
        let sealed = seal_enrollment(IKM, "bob", &seed, 1000).unwrap();
        assert!(!sealed.contains("bob"));
        let state = open_enrollment(IKM, &sealed, 1000).unwrap();
        assert_eq!(state.user_id, "bob");
        assert_eq!(state.seed, seed);
    }

    #[test]
    fn enrollment_rejects_expired_wrong_key_and_tampered() {
        let seed = generate_seed();
        let sealed = seal_enrollment(IKM, "bob", &seed, 1000).unwrap();
        let expired = 1001 + TOTP_ENROLLMENT_TTL_SECS as i64;
        assert!(matches!(
            open_enrollment(IKM, &sealed, expired),
            Err(MfaError::EnrollmentExpired)
        ));
        let bad_ikm = b"ff23456789abcdef0123456789abcdef";
        assert!(open_enrollment(bad_ikm, &sealed, 1000).is_err());
        let mut bytes = sealed.into_bytes();
        let i = bytes.len() - 2;
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        assert!(open_enrollment(IKM, &String::from_utf8(bytes).unwrap(), 1000).is_err());
    }
}
