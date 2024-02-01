use std::str::FromStr;

use crate::{
    components::{
        form::{checkbox::CheckBox, field::Field, select::Select, submit::Submit},
        router::AppRoute,
    },
    convert_attribute_type,
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        schema::AttributeType,
    },
};
use anyhow::{bail, Result};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use validator::ValidationError;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_group_attribute.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateGroupAttribute;

convert_attribute_type!(create_group_attribute::AttributeType);

pub struct CreateGroupAttributeForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<CreateGroupAttributeModel>,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default, Debug)]
pub struct CreateGroupAttributeModel {
    #[validate(length(min = 1, message = "attribute_name is required"))]
    attribute_name: String,
    #[validate(custom = "validate_attribute_type")]
    attribute_type: String,
    is_list: bool,
    is_visible: bool,
}

fn validate_attribute_type(attribute_type: &str) -> Result<(), ValidationError> {
    let result = AttributeType::from_str(attribute_type);
    match result {
        Ok(_) => Ok(()),
        _ => Err(ValidationError::new("Invalid attribute type")),
    }
}

pub enum Msg {
    Update,
    SubmitForm,
    CreateGroupAttributeResponse(Result<create_group_attribute::ResponseData>),
}

impl CommonComponent<CreateGroupAttributeForm> for CreateGroupAttributeForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitForm => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let model = self.form.model();
                let attribute_type = model.attribute_type.parse::<AttributeType>().unwrap();
                let req = create_group_attribute::Variables {
                    name: model.attribute_name,
                    attribute_type: create_group_attribute::AttributeType::from(attribute_type),
                    is_list: model.is_list,
                    is_visible: model.is_visible,
                };
                self.common.call_graphql::<CreateGroupAttribute, _>(
                    ctx,
                    req,
                    Msg::CreateGroupAttributeResponse,
                    "Error trying to create group attribute",
                );
                Ok(true)
            }
            Msg::CreateGroupAttributeResponse(response) => {
                response?;
                let model = self.form.model();
                log!(&format!(
                    "Created group attribute '{}'",
                    model.attribute_name
                ));
                ctx.link()
                    .history()
                    .unwrap()
                    .push(AppRoute::ListGroupSchema);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateGroupAttributeForm {
    type Message = Msg;
    type Properties = ();

    fn create(_: &Context<Self>) -> Self {
        let model = CreateGroupAttributeModel {
            attribute_type: AttributeType::String.to_string(),
            ..Default::default()
        };
        Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<CreateGroupAttributeModel>::new(model),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        html! {
          <div class="row justify-content-center">
            <form class="form py-3" style="max-width: 636px">
              <h5 class="fw-bold">{"Create a group attribute"}</h5>
              <Field<CreateGroupAttributeModel>
                label="Name"
                required={true}
                form={&self.form}
                field_name="attribute_name"
                oninput={link.callback(|_| Msg::Update)} />
              <Select<CreateGroupAttributeModel>
                label="Type"
                required={true}
                form={&self.form}
                field_name="attribute_type"
                oninput={link.callback(|_| Msg::Update)}>
                <option selected=true value="String">{"String"}</option>
                <option value="Integer">{"Integer"}</option>
                <option value="Jpeg">{"Jpeg"}</option>
                <option value="DateTime">{"DateTime"}</option>
              </Select<CreateGroupAttributeModel>>
              <CheckBox<CreateGroupAttributeModel>
                label="Multiple values"
                form={&self.form}
                field_name="is_list"
                ontoggle={link.callback(|_| Msg::Update)} />
              <CheckBox<CreateGroupAttributeModel>
                label="Visible to users"
                form={&self.form}
                field_name="is_visible"
                ontoggle={link.callback(|_| Msg::Update)} />
              <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})}/>
            </form>
            { if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
          </div>
        }
    }
}
