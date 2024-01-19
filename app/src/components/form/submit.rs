use web_sys::MouseEvent;
use yew::{function_component, html, Callback, Properties};

#[derive(Properties, PartialEq)]
pub struct Props {
    pub disabled: bool,
    pub onclick: Callback<MouseEvent>,
}

#[function_component(Submit)]
pub fn submit(props: &Props) -> Html {
    html! {
        <div class="form-group row justify-content-center">
            <button
                class="btn btn-primary col-auto col-form-label"
                type="submit"
                disabled={props.disabled}
                onclick={&props.onclick}>
                <i class="bi-save me-2"></i>
                {"Submit"}
            </button>
        </div>
    }
}
