use opaque_ke::ciphersuite::CipherSuite;
use rand::{CryptoRng, RngCore};

#[derive(thiserror::Error, Debug)]
pub enum AuthenticationError {
    #[error("Protocol error: `{0}`")]
    ProtocolError(#[from] opaque_ke::errors::ProtocolError),
}

pub type AuthenticationResult<T> = std::result::Result<T, AuthenticationError>;

/// Wrapper around an opaque KeyPair to have type-checked public and private keys.
#[derive(Debug, Clone)]
pub struct KeyPair(pub opaque_ke::keypair::KeyPair<<DefaultSuite as CipherSuite>::Group>);

pub struct PublicKey<'a>(&'a opaque_ke::keypair::Key);
pub struct PrivateKey<'a>(&'a opaque_ke::keypair::Key);

impl <'a> std::ops::Deref for PublicKey<'a> {
    type Target = &'a opaque_ke::keypair::Key;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl <'a> std::ops::Deref for PrivateKey<'a> {
    type Target = &'a opaque_ke::keypair::Key;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl KeyPair {
    pub fn private(&self) -> PrivateKey<'_> {
        PrivateKey(self.0.private())
    }

    pub fn public(&self) -> PublicKey<'_> {
        PublicKey(self.0.public())
    }

    pub fn from_private_key_slice(input: &[u8]) -> std::result::Result<Self, opaque_ke::errors::InternalPakeError> {
        opaque_ke::keypair::KeyPair::<<DefaultSuite as CipherSuite>::Group>::from_private_key_slice(input).map(Self)
    }
}

/// A wrapper around argon2 to provide the [`opaque_ke::slow_hash::SlowHash`] trait.
pub struct ArgonHasher;

impl ArgonHasher {
    /// Fixed salt, doesn't affect the security. It is only used to make attacks more
    /// computationally intensive, it doesn't serve any security purpose.
    const SALT: &'static [u8] = b"lldap_opaque_salt";
    /// Config for the argon hasher. Security enthusiasts may want to tweak this for their system.
    const CONFIG: &'static argon2::Config<'static> = &argon2::Config {
        ad: &[],
        hash_length: 128,
        lanes: 1,
        mem_cost: 50 * 1024, // 50 MB, in KB
        secret: &[],
        thread_mode: argon2::ThreadMode::Sequential,
        time_cost: 5,
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
    };
}

impl<D: opaque_ke::hash::Hash> opaque_ke::slow_hash::SlowHash<D> for ArgonHasher {
    fn hash(
        input: generic_array::GenericArray<u8, <D as digest::Digest>::OutputSize>,
    ) -> Result<Vec<u8>, opaque_ke::errors::InternalPakeError> {
        argon2::hash_raw(&input, Self::SALT, Self::CONFIG)
            .map_err(|_| opaque_ke::errors::InternalPakeError::HashingFailure)
    }
}

/// The ciphersuite trait allows to specify the underlying primitives
/// that will be used in the OPAQUE protocol
#[allow(dead_code)]
pub struct DefaultSuite;
impl CipherSuite for DefaultSuite {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    /// Use argon2 as the slow hashing algorithm for our CipherSuite.
    type SlowHash = ArgonHasher;
}

/// Client-side code for OPAQUE protocol handling, to register a new user and login.  All methods'
/// results must be sent to the server using the serialized `.message`. Incoming messages can be
/// deserialized using the type's `deserialize` method.
#[cfg(feature = "opaque_client")]
pub mod client {
    pub use super::*;
    /// Methods to register a new user, from the client side.
    pub mod registration {
        pub use super::*;
        pub use opaque_ke::{
            ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
            ClientRegistrationStartResult, RegistrationResponse,
        };
        /// Initiate the registration negotiation.
        pub fn start_registration<R: RngCore + CryptoRng>(
            password: &str,
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationStartResult<DefaultSuite>> {
            Ok(ClientRegistration::<DefaultSuite>::start(
                rng,
                password.as_bytes(),
            )?)
        }

        /// Finalize the registration negotiation.
        pub fn finish_registration<R: RngCore + CryptoRng>(
            registration_start: ClientRegistration<DefaultSuite>,
            registration_response: RegistrationResponse<DefaultSuite>,
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationFinishResult<DefaultSuite>> {
            Ok(registration_start.finish(
                rng,
                registration_response,
                ClientRegistrationFinishParameters::default(),
            )?)
        }
    }

    /// Methods to login, from the client side.
    pub mod login {
        pub use super::*;
        pub use opaque_ke::{
            ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
            ClientLoginStartParameters, ClientLoginStartResult, CredentialResponse,
        };

        /// Initiate the login negotiation.
        pub fn start_login<R: RngCore + CryptoRng>(
            password: &str,
            rng: &mut R,
        ) -> AuthenticationResult<ClientLoginStartResult<DefaultSuite>> {
            Ok(ClientLogin::<DefaultSuite>::start(
                rng,
                password.as_bytes(),
                ClientLoginStartParameters::default(),
            )?)
        }

        /// Finalize the client login negotiation.
        pub fn finish_login(
            login_start: ClientLogin<DefaultSuite>,
            login_response: CredentialResponse<DefaultSuite>,
        ) -> AuthenticationResult<ClientLoginFinishResult<DefaultSuite>> {
            Ok(login_start.finish(login_response, ClientLoginFinishParameters::default())?)
        }
    }
}

/// Server-side code for OPAQUE protocol handling, to register a new user and login.  The
/// intermediate results must be sent to the client using the serialized `.message`.
#[cfg(feature = "opaque_server")]
pub mod server {
    pub use super::*;
    pub use opaque_ke::ServerRegistration;
    /// Methods to register a new user, from the server side.
    pub mod registration {
        pub use super::*;
        pub use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistrationStartResult};
        /// Start a registration process, from a request sent by the client.
        ///
        /// The result must be kept for the next step.
        pub fn start_registration<R: RngCore + CryptoRng>(
            rng: &mut R,
            registration_request: RegistrationRequest<DefaultSuite>,
            server_public_key: PublicKey<'_>,
        ) -> AuthenticationResult<ServerRegistrationStartResult<DefaultSuite>> {
            Ok(ServerRegistration::<DefaultSuite>::start(
                rng,
                registration_request,
                *server_public_key,
            )?)
        }

        /// Finish to register a new user, and get the data to store in the database.
        pub fn get_password_file(
            registration_start: ServerRegistration<DefaultSuite>,
            registration_upload: RegistrationUpload<DefaultSuite>,
        ) -> AuthenticationResult<ServerRegistration<DefaultSuite>> {
            Ok(registration_start.finish(registration_upload)?)
        }
    }

    /// Methods to handle user login, from the server-side.
    pub mod login {
        pub use super::*;
        pub use opaque_ke::{
            CredentialFinalization, CredentialRequest, ServerLogin, ServerLoginFinishResult,
            ServerLoginStartParameters, ServerLoginStartResult,
        };

        /// Start a login process, from a request sent by the client.
        ///
        /// The result must be kept for the next step.
        pub fn start_login<R: RngCore + CryptoRng>(
            rng: &mut R,
            password_file: ServerRegistration<DefaultSuite>,
            server_private_key: PrivateKey<'_>,
            credential_request: CredentialRequest<DefaultSuite>,
        ) -> AuthenticationResult<ServerLoginStartResult<DefaultSuite>> {
            Ok(ServerLogin::start(
                rng,
                password_file,
                *server_private_key,
                credential_request,
                ServerLoginStartParameters::default(),
            )?)
        }

        /// Finish to authorize a new user, and get the session key to decrypt associated data.
        pub fn finalize_login(
            login_start: ServerLogin<DefaultSuite>,
            credential_finalization: CredentialFinalization<DefaultSuite>,
        ) -> AuthenticationResult<ServerLoginFinishResult> {
            Ok(login_start.finish(credential_finalization)?)
        }
    }
}
