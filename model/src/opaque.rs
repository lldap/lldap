use opaque_ke::ciphersuite::CipherSuite;
use rand::{CryptoRng, RngCore};

#[derive(thiserror::Error, Debug)]
pub enum AuthenticationError {
    #[error("Protocol error: `{0}`")]
    ProtocolError(#[from] opaque_ke::errors::ProtocolError),
}

pub type AuthenticationResult<T> = std::result::Result<T, AuthenticationError>;

pub use opaque_ke::keypair::{PrivateKey, PublicKey};
pub type KeyPair = opaque_ke::keypair::KeyPair<<DefaultSuite as CipherSuite>::Group>;

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
        pub type ClientRegistration = opaque_ke::ClientRegistration<DefaultSuite>;
        pub type ClientRegistrationStartResult =
            opaque_ke::ClientRegistrationStartResult<DefaultSuite>;
        pub type ClientRegistrationFinishResult =
            opaque_ke::ClientRegistrationFinishResult<DefaultSuite>;
        pub type RegistrationResponse = opaque_ke::RegistrationResponse<DefaultSuite>;
        pub use opaque_ke::ClientRegistrationFinishParameters;
        /// Initiate the registration negotiation.
        pub fn start_registration<R: RngCore + CryptoRng>(
            password: &str,
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationStartResult> {
            Ok(ClientRegistration::start(rng, password.as_bytes())?)
        }

        /// Finalize the registration negotiation.
        pub fn finish_registration<R: RngCore + CryptoRng>(
            registration_start: ClientRegistration,
            registration_response: RegistrationResponse,
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationFinishResult> {
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
        pub type ClientLogin = opaque_ke::ClientLogin<DefaultSuite>;
        pub type ClientLoginFinishResult = opaque_ke::ClientLoginFinishResult<DefaultSuite>;
        pub type ClientLoginStartResult = opaque_ke::ClientLoginStartResult<DefaultSuite>;
        pub type CredentialResponse = opaque_ke::CredentialResponse<DefaultSuite>;
        pub type CredentialFinalization = opaque_ke::CredentialFinalization<DefaultSuite>;
        pub use opaque_ke::{ClientLoginFinishParameters, ClientLoginStartParameters};

        /// Initiate the login negotiation.
        pub fn start_login<R: RngCore + CryptoRng>(
            password: &str,
            rng: &mut R,
        ) -> AuthenticationResult<ClientLoginStartResult> {
            Ok(ClientLogin::start(
                rng,
                password.as_bytes(),
                ClientLoginStartParameters::default(),
            )?)
        }

        /// Finalize the client login negotiation.
        pub fn finish_login(
            login_start: ClientLogin,
            login_response: CredentialResponse,
        ) -> AuthenticationResult<ClientLoginFinishResult> {
            Ok(login_start.finish(login_response, ClientLoginFinishParameters::default())?)
        }
    }
}

/// Server-side code for OPAQUE protocol handling, to register a new user and login.  The
/// intermediate results must be sent to the client using the serialized `.message`.
#[cfg(feature = "opaque_server")]
pub mod server {
    pub use super::*;
    pub type ServerRegistration = opaque_ke::ServerRegistration<DefaultSuite>;
    /// Methods to register a new user, from the server side.
    pub mod registration {
        pub use super::*;
        pub type RegistrationRequest = opaque_ke::RegistrationRequest<DefaultSuite>;
        pub type RegistrationUpload = opaque_ke::RegistrationUpload<DefaultSuite>;
        pub type ServerRegistrationStartResult =
            opaque_ke::ServerRegistrationStartResult<DefaultSuite>;
        /// Start a registration process, from a request sent by the client.
        ///
        /// The result must be kept for the next step.
        pub fn start_registration<R: RngCore + CryptoRng>(
            rng: &mut R,
            registration_request: RegistrationRequest,
            server_public_key: &PublicKey,
        ) -> AuthenticationResult<ServerRegistrationStartResult> {
            Ok(ServerRegistration::start(
                rng,
                registration_request,
                server_public_key,
            )?)
        }

        /// Finish to register a new user, and get the data to store in the database.
        pub fn get_password_file(
            registration_start: ServerRegistration,
            registration_upload: RegistrationUpload,
        ) -> AuthenticationResult<ServerRegistration> {
            Ok(registration_start.finish(registration_upload)?)
        }
    }

    /// Methods to handle user login, from the server-side.
    pub mod login {
        pub use super::*;
        pub type CredentialFinalization = opaque_ke::CredentialFinalization<DefaultSuite>;
        pub type CredentialRequest = opaque_ke::CredentialRequest<DefaultSuite>;
        pub type ServerLogin = opaque_ke::ServerLogin<DefaultSuite>;
        pub type ServerLoginStartResult = opaque_ke::ServerLoginStartResult<DefaultSuite>;
        pub type ServerLoginFinishResult = opaque_ke::ServerLoginFinishResult<DefaultSuite>;
        pub use opaque_ke::ServerLoginStartParameters;

        /// Start a login process, from a request sent by the client.
        ///
        /// The result must be kept for the next step.
        pub fn start_login<R: RngCore + CryptoRng>(
            rng: &mut R,
            password_file: ServerRegistration,
            server_private_key: &PrivateKey,
            credential_request: CredentialRequest,
        ) -> AuthenticationResult<ServerLoginStartResult> {
            Ok(ServerLogin::start(
                rng,
                password_file,
                server_private_key,
                credential_request,
                ServerLoginStartParameters::default(),
            )?)
        }

        /// Finish to authorize a new user, and get the session key to decrypt associated data.
        pub fn finish_login(
            login_start: ServerLogin,
            credential_finalization: CredentialFinalization,
        ) -> AuthenticationResult<ServerLoginFinishResult> {
            Ok(login_start.finish(credential_finalization)?)
        }
    }
}
