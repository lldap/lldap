use crate::infra::{schema::AttributeType, tooltip::Tooltip};
use web_sys::Element;
use yew::{
    function_component, html, use_effect_with_deps, use_mut_ref, use_node_ref, use_state, virtual_dom::AttrValue, Html, Properties
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
struct AttributeLabelProps {
    pub name: String,
}
#[function_component(AttributeLabel)]
fn attribute_label(props: &AttributeLabelProps) -> Html {
    let tooltip_ref = use_node_ref();
    let tooltip_js = use_mut_ref(|| None);

    {
        let tooltip_js = tooltip_js.clone();
        use_effect_with_deps(move |tooltip_ref| {
            let tooltip_ref = tooltip_ref
                .cast::<Element>()
                .expect("Tooltip element should exist");
            *tooltip_js.borrow_mut() = Some(Tooltip::new(tooltip_ref));
            || {}
        }, tooltip_ref.clone());
    }

    html! {
        <label for={props.name.clone()}
            class="form-label col-4 col-form-label"
            >
            {props.name[0..1].to_uppercase() + &props.name[1..].replace("_", " ")}{":"}
            <button
                class="btn btn-sm btn-link"
                type="button"
                data-bs-placement="right"
                title={props.name.clone()}
                // onclick={move |_| tooltip_js.borrow().as_ref().expect("Tooltip should have initialized").toggle()}
                ref={tooltip_ref}>
                <i class="bi bi-info-circle" aria-label="Info" />
            </button>
        </label>
    }

}

#[derive(Properties, PartialEq)]
pub struct SingleAttributeInputProps {
    pub name: String,
    pub attribute_type: AttributeType,
    #[prop_or(None)]
    pub value: Option<String>,
}

#[function_component(SingleAttributeInput)]
pub fn single_attribute_input(props: &SingleAttributeInputProps) -> Html {
    html! {
        <div class="row mb-3">
            <AttributeLabel name={props.name.clone()} />
            <div class="col-8">
            <AttributeInput
                attribute_type={props.attribute_type.clone()}
                name={props.name.clone()}
                value={props.value.clone()} />
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct ListAttributeInputProps {
    pub name: String,
    pub attribute_type: AttributeType,
    pub values: Vec<String>,
}

#[function_component(ListAttributeInput)]
pub fn list_attribute_input(props: &ListAttributeInputProps) -> Html {

    // let value_indices = use_memo(props.values, |vals| use_state(|| (0..(vals.len() as isize)).collect::<Vec<_>>()));
    let value_indices = use_state(|| (0..(props.values.len() as isize)).collect::<Vec<_>>() ); // use_memo(props.values)
    let new_index = use_mut_ref::<isize>(|| 0);

    html! {
        <div class="row mb-3">
            <AttributeLabel name={props.name.clone()} />
            <div class="col-8">
            {value_indices.iter().map(|i| {let i = *i; html! {
                <div class="input-group mb-2" key={i}>
                <AttributeInput
                    attribute_type={props.attribute_type.clone()}
                    name={props.name.clone()}
                    value={usize::try_from(i).ok().and_then(|i| props.values.get(i)).cloned().unwrap_or_else(|| String::from(""))} />
                <button
                    class="btn btn-danger"
                    type="button"
                    onclick={
                        let value_indices = value_indices.clone();
                        move |_| value_indices.set((*value_indices).clone().into_iter().filter(|x| *x != i).collect())
                    }>
                    <i class="bi-x-circle-fill" aria-label="Remove value" />
                </button>
                </div>
            }}).collect::<Html>()}
            <button
                class="btn btn-secondary"
                type="button"
                onclick={
                    let value_indices = value_indices.clone();
                    move |_| {
                        *new_index.borrow_mut() -= 1;
                        value_indices.set((*value_indices).clone().into_iter().chain(std::iter::once(*new_index.borrow())).collect())
                    }}>
                <i class="bi-plus-circle me-2"></i>
                {"Add value"}
            </button>
            </div>
        </div>
    }
}
