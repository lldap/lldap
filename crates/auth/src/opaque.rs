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

/// JSON wire encoding for OPAQUE protocol messages: the message's protocol
/// bytes (RFC 9807 serialization) as a base64 string. This matches the
/// pre-4.0 wire format and keeps the HTTP API decoupled from opaque-ke's
/// internal struct layout — opaque-ke 4.0's derived serde impls would
/// otherwise write nested integer arrays in JSON (see issue #111). It also
/// lets non-Rust clients produce messages from raw protocol bytes.
///
/// Use with `#[serde(with = "crate::opaque::base64_wire")]` on message
/// fields of the wire structs.
pub mod base64_wire {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    /// Bridge between serde and opaque-ke's own protocol serialization.
    pub trait WireMessage: Sized {
        fn to_wire_bytes(&self) -> Vec<u8>;
        fn from_wire_bytes(bytes: &[u8]) -> Result<Self, opaque_ke::errors::ProtocolError>;
    }

    macro_rules! impl_wire_message {
        ($($type:ident),*) => {$(
            impl WireMessage for opaque_ke::$type<super::DefaultSuite> {
                fn to_wire_bytes(&self) -> Vec<u8> {
                    self.serialize().to_vec()
                }
                fn from_wire_bytes(
                    bytes: &[u8],
                ) -> Result<Self, opaque_ke::errors::ProtocolError> {
                    Self::deserialize(bytes)
                }
            }
        )*};
    }
    impl_wire_message!(
        RegistrationRequest,
        RegistrationResponse,
        RegistrationUpload,
        CredentialRequest,
        CredentialResponse,
        CredentialFinalization
    );

    pub fn serialize<T: WireMessage, S: Serializer>(
        message: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(
            &base64::engine::general_purpose::STANDARD.encode(message.to_wire_bytes()),
        )
    }

    pub fn deserialize<'de, T: WireMessage, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(D::Error::custom)?;
        T::from_wire_bytes(&bytes)
            .map_err(|e| D::Error::custom(format!("Invalid OPAQUE message: {e:?}")))
    }
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

#[cfg(test)]
mod wire_format_tests {
    /// The public JSON API must carry OPAQUE messages as base64 strings
    /// (the pre-4.0 wire format, and issue #111's requirement) — not as
    /// opaque-ke's derived struct serialization (nested integer arrays).
    #[test]
    fn v4_messages_are_base64_strings_in_json() {
        use base64::Engine;
        let mut rng = rand::rngs::OsRng;
        let start = super::client::login::start_login("password", &mut rng).unwrap();
        let request = crate::login::ClientLoginStartRequest {
            username: crate::types::UserId::new("bob"),
            login_start_request: start.message,
        };
        let json = serde_json::to_value(&request).unwrap();
        let encoded = json["login_start_request"]
            .as_str()
            .expect("OPAQUE message must serialize to a JSON string");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("OPAQUE message string must be valid base64");
        // The base64 payload is the RFC 9807 message serialization, so it
        // must round-trip through the protocol-level deserializer.
        opaque_ke::CredentialRequest::<super::DefaultSuite>::deserialize(&bytes)
            .expect("base64 payload must be the protocol serialization");
        let roundtrip: crate::login::ClientLoginStartRequest =
            serde_json::from_value(json).unwrap();
        assert_eq!(
            roundtrip.login_start_request.serialize(),
            request.login_start_request.serialize(),
        );
    }

    /// Parity check: the v0.7 (pre-upgrade) wire format also carried the
    /// message as a single base64 string. Documents that the JSON *shape*
    /// of the API is unchanged across the opaque-ke upgrade.
    #[test]
    fn v07_messages_were_base64_strings_in_json() {
        let mut rng = rand::rngs::OsRng;
        let start =
            opaque_ke_v07::ClientLogin::<crate::v07::V07Suite>::start(&mut rng, b"password")
                .unwrap();
        let json = serde_json::to_value(&start.message).unwrap();
        assert!(
            json.is_string(),
            "v0.7 messages serialize as base64 strings"
        );
    }
}
