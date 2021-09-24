use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "bootstrap")]
extern "C" {
    #[wasm_bindgen]
    pub type Modal;

    #[wasm_bindgen(constructor)]
    pub fn new(e: web_sys::Element) -> Modal;

    #[wasm_bindgen(method)]
    pub fn show(this: &Modal);

    #[wasm_bindgen(method)]
    pub fn hide(this: &Modal);
}
