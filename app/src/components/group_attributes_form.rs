use std::ops::Deref;

use crate::{
    components::{
        group_details::Attribute,
        router::{AppRoute, Link},
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Error, Result};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct AttributeInputProps {
    pub attribute: Attribute,
    pub on_changed: Callback<(String, Vec<String>)>,
}

#[function_component(SingleAttributeInput)]
fn single_attribute_input(props: &AttributeInputProps) -> Html {
    let attribute = props.attribute.clone();
    let on_changed = props.on_changed.clone();
    let on_input = Callback::from(move |e: InputEvent| on_changed.emit((attribute.name.clone(), vec![e.data().unwrap_or_default()])));
    html!{
        <div class="row mb-3">
            <label for={props.attribute.name.clone()}
                class="form-label col-4 col-form-label">
                {props.attribute.name.clone()}
                {":"}
            </label>
            <div class="col-8">
                <input id={props.attribute.name.clone()} name={props.attribute.name.clone()} type="text" class="form-control" oninput={on_input} />
            </div>
        </div>
    }
}

#[function_component(ListAttributeInput)]
fn list_attribute_input(props: &AttributeInputProps) -> Html {
    html!{}
}

#[function_component(AttributeInput)]
fn attribute_input(props: &AttributeInputProps) -> Html {
    if props.attribute.is_list {
        html!{
            <ListAttributeInput 
                attribute={props.attribute.clone()} 
                on_changed={props.on_changed.clone()} />
        }
    } else {
        html!{
            <SingleAttributeInput 
                attribute={props.attribute.clone()} 
                on_changed={props.on_changed.clone()} />
        }
    }
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub attributes: Vec<Attribute>,
}

#[function_component(GroupAttributesForm)]
pub fn group_attributes_form(Props{ attributes }: &Props) -> Html {
    let attributes = use_state(|| attributes.clone());
    let on_changed = {
        let attributes = attributes.clone();
        Callback::from(move |(name, value): (String, Vec<String>)| {
            let mut new_attributes = attributes.deref().clone();
            new_attributes.iter_mut().filter(|attribute| attribute.name == name).for_each(|attribute| attribute.value = value.clone());
            attributes.set(new_attributes.clone());
            log!("New attributes:");
            new_attributes.iter().for_each(|attribute| log!("Name: {attribute.name}, Value: {attribute.value}"));
        })
    };
    html!{
        {for attributes.iter().map(|attribute| html!{<AttributeInput attribute={attribute.clone()} on_changed={on_changed.clone()} />})}
    }
}