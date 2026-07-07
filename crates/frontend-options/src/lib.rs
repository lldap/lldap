use serde::{Deserialize, Serialize};

/// Theme mode for the web UI.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    #[default]
    Auto,
    Light,
    Dark,
}

/// Branding customization passed from server to frontend via REST settings endpoint.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BrandingOptions {
    pub app_name: String,
    pub accent_color: Option<String>,
    pub logo_url: Option<String>,
    /// When `true`, the frontend should render the uploaded logo file
    /// served at `/branding/logo` instead of `logo_url` or the default icon.
    pub logo_file_has_been_uploaded: bool,
    pub default_theme: ThemeMode,
}

impl Default for BrandingOptions {
    fn default() -> Self {
        Self {
            app_name: "LLDAP".to_string(),
            accent_color: None,
            logo_url: None,
            logo_file_has_been_uploaded: false,
            default_theme: ThemeMode::default(),
        }
    }
}

/// Top-level settings sent from the server to the web UI at startup.
/// Gated behind a login-free `/api/...` endpoint so the frontend can read
/// it before authenticating (e.g. to apply branding on the login screen).
#[derive(Serialize, Deserialize)]
pub struct Options {
    pub password_reset_enabled: bool,
    pub branding: BrandingOptions,
}
