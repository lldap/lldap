use crate::infra::schema::AttributeType;
use yew::{
    function_component, html, virtual_dom::AttrValue, Callback, InputEvent, NodeRef, Properties,
};

/*
 <input
                ref={&ctx.props().input_ref}
                type="text"
                class="input-component"
                placeholder={placeholder}
                onmouseover={ctx.link().callback(|_| Msg::Hover)}
            />
*/

#[derive(Properties, PartialEq)]
struct AttributeInputProps {
    name: AttrValue,
    attribute_type: AttributeType,
    #[prop_or(None)]
    value: Option<String>,
}

#[function_component(AttributeInput)]
fn attribute_input(props: &AttributeInputProps) -> Html {
    let input_type = match props.attribute_type {
        AttributeType::String => "text",
        AttributeType::Integer => "number",
        AttributeType::DateTime => "datetime-local",
        AttributeType::Jpeg => "file",
    };
    let accept = match props.attribute_type {
        AttributeType::Jpeg => Some("image/jpeg"),
        _ => None,
    };
    html! {
        <input
            type={input_type}
            accept={accept}
            name={props.name.clone()}
            class="form-control"
            value={props.value.clone()} />
    }
}

#[derive(Properties, PartialEq)]
pub struct SingleAttributeInputProps {
    pub name: AttrValue,
    pub attribute_type: AttributeType,
    #[prop_or(None)]
    pub value: Option<String>,
}

#[function_component(SingleAttributeInput)]
pub fn single_attribute_input(props: &SingleAttributeInputProps) -> Html {
    html! {
        <div class="row mb-3">
            <label for={props.name.clone()}
                class="form-label col-4 col-form-label">
                {&props.name}{":"}
            </label>
            <div class="col-8">
            <AttributeInput
                attribute_type={props.attribute_type.clone()}
                name={props.name.clone()}
                value={props.value.clone()} />
            </div>
        </div>
    }
}
