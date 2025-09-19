#![recursion_limit = "256"]
#![forbid(non_ascii_idents)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::let_unit_value)]
#![allow(clippy::unnecessary_operation)] // Doesn't work well with the html macro.

pub mod components;
pub mod infra;

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<components::app::AppContainer>();

    Ok(())
}

trait DateToLocalDisplay {
    fn to_local_date_display(&self) -> impl core::fmt::Display;
    fn to_local_time_display(&self) -> impl core::fmt::Display;
}
impl<Tz: chrono::TimeZone> DateToLocalDisplay for chrono::DateTime<Tz> {
    fn to_local_date_display(&self) -> impl core::fmt::Display {
        self.with_timezone(&chrono::offset::Local).date_naive()
    }
    fn to_local_time_display(&self) -> impl core::fmt::Display {
        self.with_timezone(&chrono::offset::Local).naive_local()
    }
}
