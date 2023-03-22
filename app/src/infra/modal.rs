use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = bootstrap)]
    pub type Modal;

    #[wasm_bindgen(constructor, js_namespace = bootstrap)]
    pub fn new(e: web_sys::Element) -> Modal;

    #[wasm_bindgen(method, js_namespace = bootstrap)]
    pub fn show(this: &Modal);

    #[wasm_bindgen(method, js_namespace = bootstrap)]
    pub fn hide(this: &Modal);
}
