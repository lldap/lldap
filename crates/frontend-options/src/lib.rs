use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Options {
    pub password_reset_enabled: bool,
    /// Whether the server's MFA policy is anything other than disabled.
    #[serde(default)]
    pub mfa_enabled: bool,
}
