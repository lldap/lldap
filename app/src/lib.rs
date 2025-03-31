#![recursion_limit = "256"]
#![forbid(non_ascii_idents)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::let_unit_value)]

pub mod components;
pub mod infra;

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<components::app::AppContainer>();

    Ok(())
}
