use crate::{
    components::form::{date_input::DateTimeInput, file_input::JpegFileInput},
    infra::{schema::AttributeType, tooltip::Tooltip},
};
use web_sys::Element;
use yew::{
    Component, Context, Html, Properties, TargetCast, function_component, html,
    use_effect_with_deps, use_node_ref, virtual_dom::AttrValue,
};

#[derive(Properties, PartialEq)]
struct AttributeInputProps {
    name: AttrValue,
    attribute_type: AttributeType,
    #[prop_or(None)]
    value: Option<String>,
    #[prop_or(None)]
    onchange: Option<yew::Callback<String>>,
}

#[function_component(AttributeInput)]
fn attribute_input(props: &AttributeInputProps) -> Html {
    let input_type = match props.attribute_type {
        AttributeType::String => "text",
        AttributeType::Integer => "number",
        AttributeType::DateTime => {
            return html! {
                <DateTimeInput name={props.name.clone()} value={props.value.clone()} onchange={props.onchange.clone()} />
            };
        }
        AttributeType::Jpeg => {
            return html! {
                <JpegFileInput name={props.name.clone()} value={props.value.clone()} onchange={props.onchange.clone()} />
            };
        }
        AttributeType::Boolean => {
            let checked = props.value.as_ref().map(|v| v == "true").unwrap_or(false);
            let onchange = props.onchange.clone();
            return html! {
                <div class="form-check form-switch">
                    <input
                        class="form-check-input"
                        type="checkbox"
                        name={props.name.clone()}
                        checked={checked}
                        value="true"
                        onchange={move |e: yew::Event| {
                            if let Some(callback) = &onchange {
                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                let value = if input.checked() { "true" } else { "false" };
                                callback.emit(value.to_string());
                            }
                        }} />
                </div>
            };
        }
    };

    let onchange_callback = props.onchange.clone();
    html! {
        <input
            type={input_type}
            name={props.name.clone()}
            class="form-control"
            value={props.value.clone()}
            oninput={move |e: yew::InputEvent| {
                if let Some(callback) = &onchange_callback {
                    let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                    callback.emit(input.value());
                }
            }} />
    }
}

#[derive(Properties, PartialEq)]
struct AttributeLabelProps {
    pub name: String,
}
#[function_component(AttributeLabel)]
fn attribute_label(props: &AttributeLabelProps) -> Html {
    let tooltip_ref = use_node_ref();

    use_effect_with_deps(
        move |tooltip_ref| {
            Tooltip::new(
                tooltip_ref
                    .cast::<Element>()
                    .expect("Tooltip element should exist"),
            );
            || {}
        },
        tooltip_ref.clone(),
    );

    html! {
        <label for={props.name.clone()}
            class="form-label col-4 col-form-label"
            >
            {props.name[0..1].to_uppercase() + &props.name[1..].replace('_', " ")}{":"}
            <button
                class="btn btn-sm btn-link"
                type="button"
                data-bs-placement="right"
                title={props.name.clone()}
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
    #[prop_or(None)]
    pub onchange: Option<yew::Callback<String>>,
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
                value={props.value.clone()}
                onchange={props.onchange.clone()} />
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct ListAttributeInputProps {
    pub name: String,
    pub attribute_type: AttributeType,
    #[prop_or(vec!())]
    pub values: Vec<String>,
}

pub enum ListAttributeInputMsg {
    Remove(usize),
    Append,
}

pub struct ListAttributeInput {
    indices: Vec<usize>,
    next_index: usize,
    values: Vec<String>,
}
impl Component for ListAttributeInput {
    type Message = ListAttributeInputMsg;
    type Properties = ListAttributeInputProps;

    fn create(ctx: &Context<Self>) -> Self {
        let values = ctx.props().values.clone();
        Self {
            indices: (0..values.len()).collect(),
            next_index: values.len(),
            values,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            ListAttributeInputMsg::Remove(removed) => {
                self.indices.retain_mut(|x| *x != removed);
            }
            ListAttributeInputMsg::Append => {
                self.indices.push(self.next_index);
                self.next_index += 1;
            }
        };
        true
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        if ctx.props().values != self.values {
            self.values.clone_from(&ctx.props().values);
            self.indices = (0..self.values.len()).collect();
            self.next_index = self.values.len();
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let props = &ctx.props();
        let link = &ctx.link();
        html! {
            <div class="row mb-3">
                <AttributeLabel name={props.name.clone()} />
                <div class="col-8">
                {self.indices.iter().map(|&i| html! {
                    <div class="input-group mb-2" key={i}>
                    <AttributeInput
                        attribute_type={props.attribute_type.clone()}
                        name={props.name.clone()}
                        value={props.values.get(i).cloned().unwrap_or_default()}
                        onchange={None} />
                    <button
                        class="btn btn-danger"
                        type="button"
                        onclick={link.callback(move |_| ListAttributeInputMsg::Remove(i))}>
                        <i class="bi-x-circle-fill" aria-label="Remove value" />
                    </button>
                    </div>
                }).collect::<Html>()}
                <button
                    class="btn btn-secondary"
                    type="button"
                    onclick={link.callback(|_| ListAttributeInputMsg::Append)}>
                    <i class="bi-plus-circle me-2"></i>
                    {"Add value"}
                </button>
                </div>
            </div>
        }
    }
}
