#![forbid(non_ascii_idents)]
#![allow(clippy::nonstandard_macro_braces)]
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

pub mod opaque;

/// The messages for the 3-step OPAQUE and simple login process.
pub mod login {
    use super::*;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerData {
        pub username: String,
        pub server_login: opaque::server::login::ServerLogin,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientLoginStartRequest {
        pub username: String,
        pub login_start_request: opaque::server::login::CredentialRequest,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginStartResponse {
        /// Base64, encrypted ServerData to be passed back to the server.
        pub server_data: String,
        pub credential_response: opaque::client::login::CredentialResponse,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientLoginFinishRequest {
        /// Encrypted ServerData from the previous step.
        pub server_data: String,
        pub credential_finalization: opaque::client::login::CredentialFinalization,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientSimpleLoginRequest {
        pub username: String,
        pub password: String,
    }

    impl fmt::Debug for ClientSimpleLoginRequest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientSimpleLoginRequest")
                .field("username", &self.username)
                .field("password", &"***********")
                .finish()
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginResponse {
        pub token: String,
        #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
        pub refresh_token: Option<String>,
    }
}

/// The messages for the 3-step OPAQUE registration process.
/// It is used to reset a user's password.
pub mod registration {
    use super::*;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerData {
        pub username: String,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientRegistrationStartRequest {
        pub username: String,
        pub registration_start_request: opaque::server::registration::RegistrationRequest,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerRegistrationStartResponse {
        /// Base64, encrypted ServerData to be passed back to the server.
        pub server_data: String,
        pub registration_response: opaque::client::registration::RegistrationResponse,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientRegistrationFinishRequest {
        /// Encrypted ServerData from the previous step.
        pub server_data: String,
        pub registration_upload: opaque::server::registration::RegistrationUpload,
    }
}

/// The messages for the 3-step OPAQUE registration process.
/// It is used to reset a user's password.
pub mod password_reset {
    use super::*;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerPasswordResetResponse {
        #[serde(rename = "userId")]
        pub user_id: String,
        pub token: String,
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub exp: DateTime<Utc>,
    pub iat: DateTime<Utc>,
    pub user: String,
    pub groups: HashSet<String>,
}
