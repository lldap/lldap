//! Client-side opaque-ke 0.7 support for progressive password migration.
//!
//! This module is self-contained: it defines the legacy `CipherSuite` and
//! exposes just enough client-side helpers to perform a v0.7 OPAQUE login
//! handshake. It is only invoked when the server reports HTTP 409 with
//! `error_code: legacy_opaque_version` on a v4.0 login attempt.
//!
//! After a successful legacy login, the calling code should immediately
//! re-register the password via the current v4.0 registration flow — this
//! is what upgrades the stored password file to v4.0.

use opaque_ke_legacy::ciphersuite::CipherSuite;
use opaque_ke_legacy::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::{CryptoRng, RngCore};

/// Slow hash matching the opaque-ke 0.7 server-side `ArgonHasher` config
/// from when LLDAP first adopted OPAQUE. Must match byte-for-byte with the
/// stored password files and with `sql_opaque_handler`'s `legacy::ArgonHasher`.
pub struct ArgonHasher;

impl ArgonHasher {
    const SALT: &'static [u8] = b"lldap_opaque_salt";
    const CONFIG: &'static argon2::Config<'static> = &argon2::Config {
        ad: &[],
        hash_length: 128,
        lanes: 1,
        mem_cost: 50 * 1024,
        secret: &[],
        time_cost: 1,
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
    };
}

impl<D: opaque_ke_legacy::hash::Hash> opaque_ke_legacy::slow_hash::SlowHash<D> for ArgonHasher {
    fn hash(
        input: generic_array::GenericArray<u8, <D as digest_legacy::Digest>::OutputSize>,
    ) -> Result<Vec<u8>, opaque_ke_legacy::errors::InternalPakeError> {
        argon2::hash_raw(&input, Self::SALT, Self::CONFIG)
            .map_err(|_| opaque_ke_legacy::errors::InternalPakeError::HashingFailure)
    }
}

/// The legacy CipherSuite (opaque-ke 0.7 / pre-RFC-9807).
pub struct LegacySuite;

impl CipherSuite for LegacySuite {
    type Group = curve25519_dalek_legacy::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke_legacy::key_exchange::tripledh::TripleDH;
    type Hash = sha2_legacy::Sha512;
    type SlowHash = ArgonHasher;
}

pub type LegacyClientLogin = ClientLogin<LegacySuite>;

/// Start a legacy login handshake client-side.
/// Returns `(state, credential_request_bytes)` — the state must be kept for
/// `finish_login`, and the bytes are sent to `/auth/opaque/v0/login/start`.
pub fn start_login<R: RngCore + CryptoRng>(
    password: &str,
    rng: &mut R,
) -> anyhow::Result<(LegacyClientLogin, Vec<u8>)> {
    let result = ClientLogin::<LegacySuite>::start(rng, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("Legacy OPAQUE start_login failed: {}", e))?;
    let bytes = result.message.serialize();
    Ok((result.state, bytes))
}

/// Finish a legacy login handshake client-side, given the server's
/// `CredentialResponse` bytes (already base64-decoded).
/// Returns the `CredentialFinalization` bytes to send to
/// `/auth/opaque/v0/login/finish`.
pub fn finish_login(
    state: LegacyClientLogin,
    server_response_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let response = CredentialResponse::<LegacySuite>::deserialize(server_response_bytes)
        .map_err(|e| anyhow::anyhow!("Legacy CredentialResponse decode error: {}", e))?;
    let result = state
        .finish(response, ClientLoginFinishParameters::default())
        .map_err(|e| anyhow::anyhow!("Legacy OPAQUE finish_login failed: {}", e))?;
    Ok(result.message.serialize())
}

