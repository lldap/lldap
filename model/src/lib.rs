#![allow(clippy::nonstandard_macro_braces)]
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub mod opaque;

/// The messages for the 3-step OPAQUE login process.
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

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(sqlx::FromRow))]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    // pub avatar: ?,
    pub creation_date: chrono::DateTime<chrono::Utc>,
}

impl Default for User {
    fn default() -> Self {
        User {
            user_id: String::new(),
            email: String::new(),
            display_name: None,
            first_name: None,
            last_name: None,
            creation_date: Utc.timestamp(0, 0),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Group {
    pub display_name: String,
    pub users: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub display_name: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AddUserToGroupRequest {
    pub user_id: String,
    pub group_id: i32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub exp: DateTime<Utc>,
    pub iat: DateTime<Utc>,
    pub user: String,
    pub groups: HashSet<String>,
}
