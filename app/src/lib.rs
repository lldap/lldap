#![recursion_limit = "256"]
#![allow(clippy::nonstandard_macro_braces)]
mod api;
mod app;
mod cookies;
mod create_user;
mod graphql;
mod login;
mod logout;
mod user_details;
mod user_table;

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<app::App>();

    Ok(())
}
