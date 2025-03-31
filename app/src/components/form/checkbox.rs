use yew::{Callback, Properties, function_component, html, virtual_dom::AttrValue};
use yew_form::{Form, Model};

#[derive(Properties, PartialEq)]
pub struct Props<T: Model> {
    pub label: AttrValue,
    pub field_name: String,
    pub form: Form<T>,
    #[prop_or(false)]
    pub required: bool,
    #[prop_or_else(Callback::noop)]
    pub ontoggle: Callback<bool>,
}

#[function_component(CheckBox)]
pub fn checkbox<T: Model>(props: &Props<T>) -> Html {
    html! {
        <div class="form-group row mb-3">
            <label for={props.field_name.clone()}
                class="form-label col-4 col-form-label">
                {&props.label}
                {if props.required {
                    html!{<span class="text-danger">{"*"}</span>}
                } else {html!{}}}
                {":"}
            </label>
            <div class="col-8">
                <yew_form::CheckBox<T>
                form={&props.form}
                field_name={props.field_name.clone()}
                ontoggle={props.ontoggle.clone()} />
            </div>
        </div>
    }
}
