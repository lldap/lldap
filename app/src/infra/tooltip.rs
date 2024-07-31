#![allow(clippy::empty_docs)]

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = bootstrap)]
    pub type Tooltip;

    #[wasm_bindgen(constructor, js_namespace = bootstrap)]
    pub fn new(e: web_sys::Element) -> Tooltip;

    #[wasm_bindgen(method, js_namespace = bootstrap)]
    pub fn toggle(this: &Tooltip);
}
