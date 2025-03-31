use yew::{Callback, InputEvent, Properties, function_component, html, virtual_dom::AttrValue};
use yew_form::{Form, Model};

#[derive(Properties, PartialEq)]
pub struct Props<T: Model> {
    pub label: AttrValue,
    pub field_name: String,
    pub form: Form<T>,
    #[prop_or(false)]
    pub required: bool,
    #[prop_or(String::from("text"))]
    pub input_type: String,
    // If not present, will default to field_name
    #[prop_or(None)]
    pub autocomplete: Option<String>,
    #[prop_or_else(Callback::noop)]
    pub oninput: Callback<InputEvent>,
}

#[function_component(Field)]
pub fn field<T: Model>(props: &Props<T>) -> Html {
    html! {
      <div class="row mb-3">
        <label for={props.field_name.clone()}
          class="form-label col-4 col-form-label">
          {&props.label}
          {if props.required {
            html!{<span class="text-danger">{"*"}</span>}
          } else {html!{}}}
          {":"}
        </label>
        <div class="col-8">
          <yew_form::Field<T>
            form={&props.form}
            field_name={props.field_name.clone()}
            input_type={props.input_type.clone()}
            class="form-control"
            class_invalid="is-invalid has-error"
            class_valid="has-success"
            autocomplete={props.autocomplete.clone().unwrap_or(props.field_name.clone())}
            oninput={&props.oninput} />
            <div class="invalid-feedback">
              {&props.form.field_message(&props.field_name)}
            </div>
        </div>
      </div>
    }
}
