#![recursion_limit = "256"]
#![forbid(non_ascii_idents)]
#![allow(clippy::nonstandard_macro_braces)]
pub mod components;
pub mod infra;

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<components::app::App>();

    Ok(())
}
