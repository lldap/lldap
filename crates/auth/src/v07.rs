//! Opaque-ke 0.7 support for progressive password migration.
//!
//! This module centralises ALL opaque-ke 0.7 types and crypto operations so
//! that no other crate needs a direct dependency on `opaque-ke` 0.7.  It
//! compiles for both native and `wasm32` targets.
//!
//! After two stable LLDAP releases following the upgrade (or at v1.0), this
//! entire module can be deleted together with the `opaque-ke-v07` dependency.

use opaque_ke_v07::ciphersuite::CipherSuite;
use serde::{Deserialize, Serialize};

// -------------------------------------------------------------------------
// Shared: CipherSuite + SlowHash (single source of truth)
// -------------------------------------------------------------------------

/// Argon2 slow-hash matching the original opaque-ke 0.7 LLDAP configuration.
/// Must produce byte-identical output to the hashes stored in existing password
/// files.
pub struct ArgonHasher;

impl ArgonHasher {
    const SALT: &'static [u8] = b"lldap_opaque_salt";
    const CONFIG: &'static rust_argon2_v07::Config<'static> = &rust_argon2_v07::Config {
        ad: &[],
        hash_length: 128,
        lanes: 1,
        mem_cost: 50 * 1024,
        secret: &[],
        time_cost: 1,
        variant: rust_argon2_v07::Variant::Argon2id,
        version: rust_argon2_v07::Version::Version13,
    };
}

impl<D: opaque_ke_v07::hash::Hash> opaque_ke_v07::slow_hash::SlowHash<D> for ArgonHasher {
    fn hash(
        input: generic_array::GenericArray<u8, <D as digest_v07::Digest>::OutputSize>,
    ) -> Result<Vec<u8>, opaque_ke_v07::errors::InternalPakeError> {
        rust_argon2_v07::hash_raw(&input, Self::SALT, Self::CONFIG)
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

// -------------------------------------------------------------------------
// Server-side wrappers (used by sql-backend-handler)
// -------------------------------------------------------------------------

/// Opaque wrapper around `opaque_ke_v07::ServerSetup<V07Suite>`.
/// Downstream crates never see the inner type.
pub struct V07ServerSetup(opaque_ke_v07::ServerSetup<V07Suite>);

impl V07ServerSetup {
    /// Deserialize a v0.7 `ServerSetup` from raw bytes.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        opaque_ke_v07::ServerSetup::<V07Suite>::deserialize(bytes)
            .ok()
            .map(Self)
    }
}

/// Check if raw bytes are a valid opaque-ke 0.7 password file.
pub fn is_v07_format(bytes: &[u8]) -> bool {
    opaque_ke_v07::ServerRegistration::<V07Suite>::deserialize(bytes).is_ok()
}

/// Full in-process password validation (both sides of the OPAQUE handshake,
/// server-side only). Used by `bind()` where the server has the cleartext.
pub fn validate_password(
    password_file_bytes: &[u8],
    clear_password: &str,
    setup: &V07ServerSetup,
    username: &str,
) -> Result<(), String> {
    use opaque_ke_v07::{
        ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters,
    };
    let mut rng = rand::rngs::OsRng;

    let password_file =
        opaque_ke_v07::ServerRegistration::<V07Suite>::deserialize(password_file_bytes)
            .map_err(|e| format!("v0.7 password deserialization error: {e}"))?;
    let client_login_start = ClientLogin::<V07Suite>::start(&mut rng, clear_password.as_bytes())
        .map_err(|e| format!("v0.7 login start error: {e}"))?;
    let server_login_start = ServerLogin::<V07Suite>::start(
        &mut rng,
        &setup.0,
        Some(password_file),
        client_login_start.message,
        username.as_bytes(),
        ServerLoginStartParameters::default(),
    )
    .map_err(|e| format!("v0.7 server login error: {e}"))?;
    client_login_start
        .state
        .finish(
            server_login_start.message,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|e| format!("v0.7 login finish error: {e}"))?;
    Ok(())
}

/// Opaque server login state for round-tripping through the untrusted client.
/// `Serialize`/`Deserialize` so sql-backend-handler can encrypt it with orion.
#[derive(Serialize, Deserialize)]
pub struct V07ServerLoginState(opaque_ke_v07::ServerLogin<V07Suite>);

/// Server-side v0.7 login start. Returns the opaque server login state (for
/// serialization by the caller) and the raw `CredentialResponse` bytes.
///
/// `password_file_bytes` is `None` for dummy handshakes (user doesn't exist).
pub fn server_login_start(
    setup: &V07ServerSetup,
    credential_request_bytes: &[u8],
    password_file_bytes: Option<&[u8]>,
    username: &str,
) -> Result<(V07ServerLoginState, Vec<u8>), String> {
    let credential_request =
        opaque_ke_v07::CredentialRequest::<V07Suite>::deserialize(credential_request_bytes)
            .map_err(|e| format!("v0.7 CredentialRequest decode error: {e}"))?;
    let password_file = password_file_bytes
        .map(|bytes| {
            opaque_ke_v07::ServerRegistration::<V07Suite>::deserialize(bytes)
                .map_err(|e| format!("Corrupted v0.7 password file: {e}"))
        })
        .transpose()?;

    let mut rng = rand::rngs::OsRng;
    let start_response = opaque_ke_v07::ServerLogin::<V07Suite>::start(
        &mut rng,
        &setup.0,
        password_file,
        credential_request,
        username.as_bytes(),
        opaque_ke_v07::ServerLoginStartParameters::default(),
    )
    .map_err(|e| format!("v0.7 server login start error: {e}"))?;

    let response_bytes = start_response.message.serialize();
    Ok((V07ServerLoginState(start_response.state), response_bytes))
}

/// Server-side v0.7 login finish. Returns `Ok(())` if credentials are valid.
pub fn server_login_finish(
    state: V07ServerLoginState,
    credential_finalization_bytes: &[u8],
) -> Result<(), String> {
    let credential_finalization =
        opaque_ke_v07::CredentialFinalization::<V07Suite>::deserialize(credential_finalization_bytes)
            .map_err(|e| format!("v0.7 CredentialFinalization decode error: {e}"))?;
    state
        .0
        .finish(credential_finalization)
        .map_err(|e| format!("v0.7 login validation failed: {e}"))?;
    Ok(())
}

// -------------------------------------------------------------------------
// Client-side wrappers (used by app / WASM)
// -------------------------------------------------------------------------

/// Opaque client login state (non-serializable, lives in WASM memory).
pub struct V07ClientLoginState(opaque_ke_v07::ClientLogin<V07Suite>);

/// Client-side v0.7 login start.
/// Returns `(state, credential_request_bytes)`.
pub fn client_login_start(password: &str) -> Result<(V07ClientLoginState, Vec<u8>), String> {
    let mut rng = rand::rngs::OsRng;
    let result = opaque_ke_v07::ClientLogin::<V07Suite>::start(&mut rng, password.as_bytes())
        .map_err(|e| format!("v0.7 OPAQUE start_login failed: {e}"))?;
    let bytes = result.message.serialize();
    Ok((V07ClientLoginState(result.state), bytes))
}

/// Client-side v0.7 login finish, given the server's `CredentialResponse`
/// bytes (already base64-decoded).
/// Returns the `CredentialFinalization` bytes.
pub fn client_login_finish(
    state: V07ClientLoginState,
    server_response_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let response =
        opaque_ke_v07::CredentialResponse::<V07Suite>::deserialize(server_response_bytes)
            .map_err(|e| format!("v0.7 CredentialResponse decode error: {e}"))?;
    let result = state
        .0
        .finish(response, opaque_ke_v07::ClientLoginFinishParameters::default())
        .map_err(|e| format!("v0.7 OPAQUE finish_login failed: {e}"))?;
    Ok(result.message.serialize())
}

// -------------------------------------------------------------------------
// Test helper: create v0.7 password files for integration tests
// -------------------------------------------------------------------------

/// Create a v0.7 password file for the given user.
/// Returns `(password_file_bytes, server_setup_bytes)`.
///
/// Available unconditionally (gated by the `test` feature on lldap_auth)
/// so that `sql-backend-handler` tests can call it.
#[cfg(feature = "test")]
pub fn create_test_password_file(username: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng;
    let v07_setup = opaque_ke_v07::ServerSetup::<V07Suite>::new(&mut rng);

    let client_start =
        opaque_ke_v07::ClientRegistration::<V07Suite>::start(&mut rng, password.as_bytes())
            .unwrap();
    let server_start = opaque_ke_v07::ServerRegistration::<V07Suite>::start(
        &v07_setup,
        client_start.message,
        username.as_bytes(),
    )
    .unwrap();
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            server_start.message,
            opaque_ke_v07::ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let v07_password_file =
        opaque_ke_v07::ServerRegistration::<V07Suite>::finish(client_finish.message);
    (v07_password_file.serialize(), v07_setup.serialize())
}
