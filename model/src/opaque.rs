use opaque_ke::ciphersuite::CipherSuite;
use rand::{CryptoRng, RngCore};

#[derive(thiserror::Error, Debug)]
pub enum AuthenticationError {
    #[error("Protocol error: `{0}`")]
    ProtocolError(#[from] opaque_ke::errors::ProtocolError),
}

pub type AuthenticationResult<T> = std::result::Result<T, AuthenticationError>;

/// The ciphersuite trait allows to specify the underlying primitives
/// that will be used in the OPAQUE protocol
#[allow(dead_code)]
pub struct DefaultSuite;
impl CipherSuite for DefaultSuite {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

/// Client-side code for OPAQUE protocol handling, to register a new user and login.  All methods'
/// results must be sent to the server using the serialized `.message`. Incoming messages can be
/// deserialized using the type's `deserialize` method.
#[cfg(feature = "opaque_client")]
pub mod client {
    use super::*;
    /// Methods to register a new user, from the client side.
    pub mod registration {
        use super::*;
        use opaque_ke::{
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
        use super::*;
        use opaque_ke::{
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
    use super::*;
    use opaque_ke::{keypair::Key, ServerRegistration};
    /// Methods to register a new user, from the server side.
    pub mod registration {
        use super::*;
        use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistrationStartResult};
        /// Start a registration process, from a request sent by the client.
        ///
        /// The result must be kept for the next step.
        pub fn start_registration<R: RngCore + CryptoRng>(
            rng: &mut R,
            registration_request: RegistrationRequest<DefaultSuite>,
            server_public_key: &Key,
        ) -> AuthenticationResult<ServerRegistrationStartResult<DefaultSuite>> {
            Ok(ServerRegistration::<DefaultSuite>::start(
                rng,
                registration_request,
                server_public_key,
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
        use super::*;
        use opaque_ke::{
            CredentialFinalization, CredentialRequest, ServerLogin, ServerLoginFinishResult,
            ServerLoginStartParameters, ServerLoginStartResult,
        };

        /// Start a login process, from a request sent by the client.
        ///
        /// The result must be kept for the next step.
        pub fn start_login<R: RngCore + CryptoRng>(
            rng: &mut R,
            password_file: ServerRegistration<DefaultSuite>,
            server_private_key: &Key,
            credential_request: CredentialRequest<DefaultSuite>,
        ) -> AuthenticationResult<ServerLoginStartResult<DefaultSuite>> {
            Ok(ServerLogin::start(
                rng,
                password_file,
                server_private_key,
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
