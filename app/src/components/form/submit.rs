use web_sys::MouseEvent;
use yew::{function_component, html, virtual_dom::AttrValue, Callback, Children, Properties};

#[derive(Properties, PartialEq)]
pub struct Props {
    pub disabled: bool,
    pub onclick: Callback<MouseEvent>,
    // Additional elements to insert after the button, in the same div
    #[prop_or_default]
    pub children: Children,
    #[prop_or(AttrValue::from("Submit"))]
    pub text: AttrValue,
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
          {props.text.clone()}
        </button>
        {for props.children.iter()}
      </div>
    }
}
