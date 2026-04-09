//! Client-side opaque-ke 0.7 support for progressive password migration.
//!
//! This module is self-contained: it defines the v0.7 `CipherSuite` and
//! exposes just enough client-side helpers to perform a v0.7 OPAQUE login
//! handshake. It is only invoked when the server reports HTTP 409 with
//! `error_code: "opaque_v07_version"` on a v4.0 login attempt.
//!
//! After a successful v0.7 login, the calling code should immediately
//! re-register the password via the current v4.0 registration flow — this
//! is what upgrades the stored password file to v4.0.

use opaque_ke_v07::ciphersuite::CipherSuite;
use opaque_ke_v07::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::{CryptoRng, RngCore};

/// Slow hash matching the opaque-ke 0.7 server-side `ArgonHasher` config
/// from when LLDAP first adopted OPAQUE. Must match byte-for-byte with the
/// stored password files and with `sql_opaque_handler`'s `v07::ArgonHasher`.
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

impl<D: opaque_ke_v07::hash::Hash> opaque_ke_v07::slow_hash::SlowHash<D> for ArgonHasher {
    fn hash(
        input: generic_array::GenericArray<u8, <D as digest_v07::Digest>::OutputSize>,
    ) -> Result<Vec<u8>, opaque_ke_v07::errors::InternalPakeError> {
        argon2::hash_raw(&input, Self::SALT, Self::CONFIG)
            .map_err(|_| opaque_ke_v07::errors::InternalPakeError::HashingFailure)
    }
}

/// The v0.7 CipherSuite (opaque-ke 0.7 / pre-RFC-9807).
pub struct V07Suite;

impl CipherSuite for V07Suite {
    type Group = curve25519_dalek_v07::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke_v07::key_exchange::tripledh::TripleDH;
    type Hash = sha2_v07::Sha512;
    type SlowHash = ArgonHasher;
}

pub type V07ClientLogin = ClientLogin<V07Suite>;

/// Start a v0.7 login handshake client-side.
/// Returns `(state, credential_request_bytes)` — the state must be kept for
/// `finish_login`, and the bytes are sent to `/auth/opaque/v07/login/start`.
pub fn start_login<R: RngCore + CryptoRng>(
    password: &str,
    rng: &mut R,
) -> anyhow::Result<(V07ClientLogin, Vec<u8>)> {
    let result = ClientLogin::<V07Suite>::start(rng, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("v0.7 OPAQUE start_login failed: {}", e))?;
    let bytes = result.message.serialize();
    Ok((result.state, bytes))
}

/// Finish a v0.7 login handshake client-side, given the server's
/// `CredentialResponse` bytes (already base64-decoded).
/// Returns the `CredentialFinalization` bytes to send to
/// `/auth/opaque/v07/login/finish`.
pub fn finish_login(
    state: V07ClientLogin,
    server_response_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let response = CredentialResponse::<V07Suite>::deserialize(server_response_bytes)
        .map_err(|e| anyhow::anyhow!("v0.7 CredentialResponse decode error: {}", e))?;
    let result = state
        .finish(response, ClientLoginFinishParameters::default())
        .map_err(|e| anyhow::anyhow!("v0.7 OPAQUE finish_login failed: {}", e))?;
    Ok(result.message.serialize())
}
