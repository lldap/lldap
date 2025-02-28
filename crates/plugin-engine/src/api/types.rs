use std::{collections::BTreeMap, path::PathBuf};

use crate::api::backend::BackendAPI;
use lldap_auth::access_control::ValidationResults;

pub enum PluginSource {
    ScriptFile(PathBuf),
    ScriptSource(String),
}

impl PluginSource {
    pub fn from_path(path: PathBuf) -> Result<Self, String> {
        match path.try_exists() {
            Ok(true) => {
                if PluginSource::is_lua(&path) {
                    Ok(PluginSource::ScriptFile(path))
                } else {
                    Err("Unrecognized file type".to_string())
                }
            }
            Ok(false) => Err("file does not exist".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn is_lua(path: &PathBuf) -> bool {
        path.is_file()
            && path
                .extension()
                .filter(|s| s.eq_ignore_ascii_case("lua"))
                .is_some()
    }
}

impl std::fmt::Display for PluginSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginSource::ScriptFile(p) => {
                write!(
                    f,
                    "{}",
                    p.file_name().map(|f| f.to_str()).flatten().unwrap_or("n/a")
                )
            }
            PluginSource::ScriptSource(s) => {
                write!(f, "<script: '{} [...]'>", &s.as_str()[0..30])
            }
        }
    }
}

pub struct PluginConfig {
    pub plugin_source: PluginSource,
    pub kvscope: Option<String>,
    pub allow_on_password_update: bool,
    pub configuration: BTreeMap<String, String>,
}

impl PluginConfig {
    pub fn from(
        path: PathBuf,
        kv_scope: Option<String>,
        allow_on_password_update: bool,
        configuration: BTreeMap<String, String>,
    ) -> Result<Self, String> {
        Ok(PluginConfig {
            plugin_source: PluginSource::from_path(path)?,
            kvscope: kv_scope,
            allow_on_password_update,
            configuration,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PluginContext<A: BackendAPI + 'static> {
    pub api: &'static A,
    pub credentials: Option<ValidationResults>,
}

impl<A: BackendAPI> PluginContext<A> {
    pub fn new(api: &'static A, credentials: Option<ValidationResults>) -> Self {
        PluginContext { api, credentials }
    }
}
