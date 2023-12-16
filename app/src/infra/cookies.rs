use anyhow::{anyhow, Result};
use chrono::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlDocument;

fn get_document() -> Result<HtmlDocument> {
    web_sys::window()
        .and_then(|w| w.document())
        .ok_or_else(|| anyhow!("Could not get window document"))
        .and_then(|d| {
            d.dyn_into::<web_sys::HtmlDocument>()
                .map_err(|_| anyhow!("Document is not an HTMLDocument"))
        })
}

pub fn set_cookie(cookie_name: &str, value: &str, expiration: &DateTime<Utc>) -> Result<()> {
    let doc = web_sys::window()
        .and_then(|w| w.document())
        .ok_or_else(|| anyhow!("Could not get window document"))
        .and_then(|d| {
            d.dyn_into::<web_sys::HtmlDocument>()
                .map_err(|_| anyhow!("Document is not an HTMLDocument"))
        })?;
    let cookie_string = format!(
        "{}={}; expires={}; sameSite=Strict; path={}/",
        cookie_name,
        value,
        expiration.to_rfc2822(),
        yew_router::utils::base_url().unwrap_or_default()
    );
    doc.set_cookie(&cookie_string)
        .map_err(|_| anyhow!("Could not set cookie"))
}

pub fn get_cookie(cookie_name: &str) -> Result<Option<String>> {
    let cookies = get_document()?
        .cookie()
        .map_err(|_| anyhow!("Could not access cookies"))?;
    Ok(cookies
        .split(';')
        .filter_map(|c| c.split_once('='))
        .find_map(|(name, value)| {
            if name.trim() == cookie_name {
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            } else {
                None
            }
        }))
}

pub fn delete_cookie(cookie_name: &str) -> Result<()> {
    if get_cookie(cookie_name)?.is_some() {
        set_cookie(
            cookie_name,
            "",
            &Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(),
        )
    } else {
        Ok(())
    }
}
