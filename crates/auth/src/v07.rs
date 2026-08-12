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

    /// Raw private key bytes of the v0.7 server keypair.
    ///
    /// Pre-4.0 servers recorded `stable_hash(<these bytes>)` in the database
    /// (`Configuration::get_private_key_info`), so this is the value to hash
    /// when checking whether a v0.7 key is the one the server was using at
    /// its last successful startup.
    pub fn private_key_bytes(&self) -> &[u8] {
        self.0.keypair().private()
    }
}

/// Check if raw bytes are a valid opaque-ke 0.7 password file.
pub fn is_v07_format(bytes: &[u8]) -> bool {
    opaque_ke_v07::ServerRegistration::<V07Suite>::deserialize(bytes).is_ok()
}

/// Reconstruct the raw bytes of the v0.7 `ServerSetup` that a pre-4.0 server
/// derived from a `key_seed`.
///
/// The original (opaque-ke 0.7) server generated its key with
/// `ChaCha20Rng::from_seed(stable_hash(seed))` followed by
/// `ServerSetup::new(rng)`. We reproduce that exactly here — same RNG
/// algorithm (rand_chacha 0.3) and the same `CipherSuite` (`V07Suite`, which
/// is byte-identical to the pre-4.0 `DefaultSuite`) — so seed-based
/// deployments can still validate and progressively upgrade passwords that
/// were registered under opaque-ke 0.7. `seed` is the already-hashed
/// 32-byte seed (i.e. `stable_hash(key_seed)`).
pub fn v07_server_setup_bytes_from_seed(seed: [u8; 32]) -> Vec<u8> {
    // Use rand_chacha's own re-exported `rand_core` so the `SeedableRng` trait
    // matches the version `ChaCha20Rng` implements, regardless of which `rand`
    // the rest of the workspace resolves to. Byte-for-byte reproduction of the
    // pre-4.0 seed-derived key is guarded end-to-end by test_opaque_upgrade.sh
    // (seed variant) and the unit tests below.
    use rand_chacha::rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    opaque_ke_v07::ServerSetup::<V07Suite>::new(&mut rng).serialize()
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
    let credential_finalization = opaque_ke_v07::CredentialFinalization::<V07Suite>::deserialize(
        credential_finalization_bytes,
    )
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
        .finish(
            response,
            opaque_ke_v07::ClientLoginFinishParameters::default(),
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Register a v0.7 password file under a *specific* ServerSetup, mirroring
    /// the registration the pre-4.0 server performed.
    fn register_under(
        setup: &opaque_ke_v07::ServerSetup<V07Suite>,
        username: &str,
        password: &str,
    ) -> Vec<u8> {
        let mut rng = rand::rngs::OsRng;
        let client_start =
            opaque_ke_v07::ClientRegistration::<V07Suite>::start(&mut rng, password.as_bytes())
                .unwrap();
        let server_start = opaque_ke_v07::ServerRegistration::<V07Suite>::start(
            setup,
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
        opaque_ke_v07::ServerRegistration::<V07Suite>::finish(client_finish.message).serialize()
    }

    #[test]
    fn seed_derivation_is_deterministic() {
        let seed = [42u8; 32];
        assert_eq!(
            v07_server_setup_bytes_from_seed(seed),
            v07_server_setup_bytes_from_seed(seed),
            "v0.7 seed-derived key must be reproducible across restarts"
        );
        assert_ne!(
            v07_server_setup_bytes_from_seed([1u8; 32]),
            v07_server_setup_bytes_from_seed([2u8; 32]),
            "different seeds must derive different v0.7 keys"
        );
    }

    /// The crux of the seed-based migration: a password registered under the
    /// seed-derived v0.7 key must still validate after the key is re-derived
    /// from the same seed on a later startup (no key file, no sidecar).
    #[test]
    fn password_registered_under_seed_key_validates_after_rederivation() {
        let seed = [7u8; 32];
        let setup_bytes = v07_server_setup_bytes_from_seed(seed);
        let setup = opaque_ke_v07::ServerSetup::<V07Suite>::deserialize(&setup_bytes).unwrap();
        let pw_file = register_under(&setup, "alice", "correct horse battery staple");

        // Simulate a restart: key reconstructed purely from the seed.
        let rederived = V07ServerSetup::deserialize(&v07_server_setup_bytes_from_seed(seed))
            .expect("re-derived v0.7 key must deserialize");

        validate_password(
            &pw_file,
            "correct horse battery staple",
            &rederived,
            "alice",
        )
        .expect("seed-rederived key must validate the v0.7 password");
        validate_password(&pw_file, "wrong", &rederived, "alice")
            .expect_err("wrong password must be rejected");
    }
}
