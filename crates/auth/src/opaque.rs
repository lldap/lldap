use crate::types::UserId;
pub use opaque_ke::ServerLoginParameters;
use rand::{CryptoRng, RngCore};
pub type KeyPair = opaque_ke::keypair::KeyPair<opaque_ke::Ristretto255>;

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
impl opaque_ke::CipherSuite for DefaultSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange =
        opaque_ke::key_exchange::tripledh::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
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
            password: &[u8],
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationStartResult> {
            Ok(ClientRegistration::start(rng, password)?)
        }

        /// Finalize the registration negotiation.
        pub fn finish_registration<R: RngCore + CryptoRng>(
            registration_start: ClientRegistration,
            registration_response: RegistrationResponse,
            password: &[u8],
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationFinishResult> {
            Ok(registration_start.finish(
                rng,
                password,
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
        pub use opaque_ke::ClientLoginFinishParameters;

        /// Initiate the login negotiation.
        pub fn start_login<R: RngCore + CryptoRng>(
            password: &str,
            rng: &mut R,
        ) -> AuthenticationResult<ClientLoginStartResult> {
            Ok(ClientLogin::start(rng, password.as_bytes())?)
        }

        /// Finalize the client login negotiation.
        pub fn finish_login<R: RngCore + CryptoRng>(
            login_start: ClientLogin,
            login_response: CredentialResponse,
            password: &str,
            rng: &mut R,
        ) -> AuthenticationResult<ClientLoginFinishResult> {
            Ok(login_start.finish(
                rng,
                password.as_bytes(),
                login_response,
                ClientLoginFinishParameters::default(),
            )?)
        }
    }
}

/// Server-side code for OPAQUE protocol handling, to register a new user and login.  The
/// intermediate results must be sent to the client using the serialized `.message`.
#[cfg(feature = "opaque_server")]
pub mod server {
    pub use super::*;
    pub type ServerRegistration = opaque_ke::ServerRegistration<DefaultSuite>;
    pub type ServerSetup = opaque_ke::ServerSetup<DefaultSuite>;

    pub fn generate_random_private_key() -> ServerSetup {
        let mut rng = rand::rngs::OsRng;
        ServerSetup::new(&mut rng)
    }

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
        pub fn start_registration(
            server_setup: &ServerSetup,
            registration_request: RegistrationRequest,
            username: &UserId,
        ) -> AuthenticationResult<ServerRegistrationStartResult> {
            Ok(ServerRegistration::start(
                server_setup,
                registration_request,
                username.as_str().as_bytes(),
            )?)
        }

        /// Finish to register a new user, and get the data to store in the database.
        pub fn get_password_file(registration_upload: RegistrationUpload) -> ServerRegistration {
            ServerRegistration::finish(registration_upload)
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
        pub use opaque_ke::ServerLoginParameters;

        /// Start a login process, from a request sent by the client.
        ///
        /// The result must be kept for the next step.
        pub fn start_login<R: RngCore + CryptoRng>(
            rng: &mut R,
            server_setup: &ServerSetup,
            password_file: Option<ServerRegistration>,
            credential_request: CredentialRequest,
            username: &UserId,
        ) -> AuthenticationResult<ServerLoginStartResult> {
            Ok(ServerLogin::start(
                rng,
                server_setup,
                password_file,
                credential_request,
                username.as_str().as_bytes(),
                ServerLoginParameters::default(),
            )?)
        }

        /// Finish to authorize a new user, and get the session key to decrypt associated data.
        pub fn finish_login(
            login_start: ServerLogin,
            credential_finalization: CredentialFinalization,
        ) -> AuthenticationResult<ServerLoginFinishResult> {
            Ok(login_start.finish(credential_finalization, ServerLoginParameters::default())?)
        }
    }
}
