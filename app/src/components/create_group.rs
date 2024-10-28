use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            field::Field,
            submit::Submit,
        },
        router::AppRoute,
    },
    convert_attribute_type,
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::{
            read_all_form_attributes, AttributeValue, EmailIsRequired, GraphQlAttributeSchema,
            IsAdmin,
        },
        schema::AttributeType,
    },
};
use anyhow::{ensure, Result};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_attributes_schema.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupAttributesSchema;

use get_group_attributes_schema::ResponseData;

pub type Attribute =
    get_group_attributes_schema::GetGroupAttributesSchemaSchemaGroupSchemaAttributes;

convert_attribute_type!(get_group_attributes_schema::AttributeType);

impl From<&Attribute> for GraphQlAttributeSchema {
    fn from(attr: &Attribute) -> Self {
        Self {
            name: attr.name.clone(),
            is_list: attr.is_list,
            is_readonly: attr.is_readonly,
            is_editable: false, // Need to be admin to edit it.
        }
    }
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateGroup;

pub struct CreateGroupForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<CreateGroupModel>,
    attributes_schema: Option<Vec<Attribute>>,
    form_ref: NodeRef,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct CreateGroupModel {
    #[validate(length(min = 1, message = "Groupname is required"))]
    groupname: String,
}

pub enum Msg {
    Update,
    ListAttributesResponse(Result<ResponseData>),
    SubmitForm,
    CreateGroupResponse(Result<create_group::ResponseData>),
}

impl CommonComponent<CreateGroupForm> for CreateGroupForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitForm => {
                ensure!(self.form.validate(), "Check the form for errors");

                let all_values = read_all_form_attributes(
                    self.attributes_schema.iter().flatten(),
                    &self.form_ref,
                    IsAdmin(true),
                    EmailIsRequired(false),
                )?;
                let attributes = Some(
                    all_values
                        .into_iter()
                        .filter(|a| !a.values.is_empty())
                        .map(
                            |AttributeValue { name, values }| create_group::AttributeValueInput {
                                name,
                                value: values,
                            },
                        )
                        .collect(),
                );

                let model = self.form.model();
                let req = create_group::Variables {
                    group: create_group::CreateGroupInput {
                        displayName: model.groupname,
                        attributes,
                    },
                };
                self.common.call_graphql::<CreateGroup, _>(
                    ctx,
                    req,
                    Msg::CreateGroupResponse,
                    "Error trying to create group",
                );
                Ok(true)
            }
            Msg::CreateGroupResponse(response) => {
                log!(&format!(
                    "Created group '{}'",
                    &response?.create_group_with_details.display_name
                ));
                ctx.link().history().unwrap().push(AppRoute::ListGroups);
                Ok(true)
            }
            Msg::ListAttributesResponse(schema) => {
                self.attributes_schema =
                    Some(schema?.schema.group_schema.attributes.into_iter().collect());
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateGroupForm {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<CreateGroupModel>::new(CreateGroupModel::default()),
            attributes_schema: None,
            form_ref: NodeRef::default(),
        };
        component
            .common
            .call_graphql::<GetGroupAttributesSchema, _>(
                ctx,
                get_group_attributes_schema::Variables {},
                Msg::ListAttributesResponse,
                "Error trying to fetch group schema",
            );
        component
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        html! {
          <div class="row justify-content-center">
            <form class="form py-3" style="max-width: 636px"
              ref={self.form_ref.clone()}>
              <div class="row mb-3">
                <h5 class="fw-bold">{"Create a group"}</h5>
              </div>
              <Field<CreateGroupModel>
                form={&self.form}
                required=true
                label="Group name"
                field_name="groupname"
                oninput={link.callback(|_| Msg::Update)} />
              {
                  self.attributes_schema
                      .iter()
                      .flatten()
                      .filter(|a| !a.is_readonly && a.name != "display_name")
                      .map(get_custom_attribute_input)
                      .collect::<Vec<_>>()
              }
              <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})} />
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

fn get_custom_attribute_input(attribute_schema: &Attribute) -> Html {
    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
                name={attribute_schema.name.clone()}
                attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
                name={attribute_schema.name.clone()}
                attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())}
            />
        }
    }
}
