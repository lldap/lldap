use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Theme mode for the web UI.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    #[default]
    Auto,
    Light,
    Dark,
}

impl fmt::Display for ThemeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThemeMode::Auto => write!(f, "auto"),
            ThemeMode::Light => write!(f, "light"),
            ThemeMode::Dark => write!(f, "dark"),
        }
    }
}

impl FromStr for ThemeMode {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(ThemeMode::Auto),
            "light" => Ok(ThemeMode::Light),
            "dark" => Ok(ThemeMode::Dark),
            _ => Err(()),
        }
    }
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
/// Served at `GET /settings` (login-free) so the frontend can read
/// branding and password-reset configuration before authenticating.
#[derive(Serialize, Deserialize)]
pub struct Options {
    pub password_reset_enabled: bool,
    pub branding: BrandingOptions,
}
