use yew::{
    function_component, html, virtual_dom::AttrValue, Callback, Children, InputEvent, Properties,
};
use yew_form::{Form, Model};

#[derive(Properties, PartialEq)]
pub struct Props<T: Model> {
    pub label: AttrValue,
    pub field_name: String,
    pub form: Form<T>,
    #[prop_or(false)]
    pub required: bool,
    #[prop_or_else(Callback::noop)]
    pub oninput: Callback<InputEvent>,
    pub children: Children,
}

#[function_component(Select)]
pub fn select<T: Model>(props: &Props<T>) -> Html {
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
                <yew_form::Select<T>
                    form={&props.form}
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    field_name={props.field_name.clone()}
                    oninput={&props.oninput} >
                    {for props.children.iter()}
                </yew_form::Select<T>>
                <div class="invalid-feedback">
                    {&props.form.field_message(&props.field_name)}
                </div>
            </div>
        </div>
    }
}
