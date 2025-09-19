use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            static_value::StaticValue,
            submit::Submit,
        },
        user_details::{Attribute, AttributeSchema, User},
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::{AttributeValue, EmailIsRequired, IsAdmin, read_all_form_attributes},
        schema::AttributeType,
    },
};
use anyhow::{Ok, Result};
use gloo_console::console;
use graphql_client::GraphQLQuery;
use yew::prelude::*;

/// The GraphQL query sent to the server to update the user details.
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/update_user.graphql",
    response_derives = "Debug",
    variables_derives = "Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdateUser;

/// A [yew::Component] to display the user details, with a form allowing to edit them.
pub struct UserDetailsForm {
    common: CommonComponentParts<Self>,
    /// True if we just successfully updated the user, to display a success message.
    just_updated: bool,
    user: User,
    form_ref: NodeRef,
}

pub enum Msg {
    /// A form field changed.
    Update,
    /// The "Submit" button was clicked.
    SubmitClicked,
    /// We got the response from the server about our update message.
    UserUpdated(Result<update_user::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    /// The current user details.
    pub user: User,
    pub user_attributes_schema: Vec<AttributeSchema>,
    pub is_admin: bool,
    pub is_edited_user_admin: bool,
}

impl CommonComponent<UserDetailsForm> for UserDetailsForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitClicked => self.submit_user_update_form(ctx),
            Msg::UserUpdated(Err(e)) => Err(e),
            Msg::UserUpdated(Result::Ok(_)) => {
                self.just_updated = true;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for UserDetailsForm {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            just_updated: false,
            user: ctx.props().user.clone(),
            form_ref: NodeRef::default(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.just_updated = false;
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();

        let can_edit =
            |a: &AttributeSchema| (ctx.props().is_admin || a.is_editable) && !a.is_readonly;
        let display_field = |a: &AttributeSchema| {
            if can_edit(a) {
                get_custom_attribute_input(a, &self.user.attributes)
            } else {
                get_custom_attribute_static(a, &self.user.attributes)
            }
        };
        html! {
          <div class="py-3">
            <form
              class="form"
              ref={self.form_ref.clone()}>
              <StaticValue label="User ID" id="userId">
                <i>{&self.user.id}</i>
              </StaticValue>
              {
                  ctx
                      .props()
                      .user_attributes_schema
                      .iter()
                      .filter(|a| a.is_hardcoded && a.name != "user_id")
                      .map(display_field)
                      .collect::<Vec<_>>()
              }
              {
                  ctx
                      .props()
                      .user_attributes_schema
                      .iter()
                      .filter(|a| !a.is_hardcoded)
                      .map(display_field)
                      .collect::<Vec<_>>()
              }
              <Submit
                text="Save changes"
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitClicked})} />
            </form>
            {
              if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            <div hidden={!self.just_updated}>
              <div class="alert alert-success mt-4">{"User successfully updated!"}</div>
            </div>
          </div>
        }
    }
}

fn get_custom_attribute_input(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
) -> Html {
    let mut values = user_attributes
        .iter()
        .find(|a| a.name == attribute_schema.name)
        .map(|attribute| attribute.value.clone())
        .unwrap_or_default();
    let value_to_str = match attribute_schema.attribute_type {
        AttributeType::String | AttributeType::Integer => |v: String| v,
        AttributeType::DateTime => |v: String| {
            console!(format!("Parsing date: {}", &v));
            chrono::DateTime::parse_from_rfc3339(&v)
                .map(|dt| dt.with_timezone(&chrono::offset::Local).naive_local().to_string())
                .unwrap_or_else(|_| "Invalid date".to_string())
        },
        AttributeType::JpegPhoto => |_: String| "Unimplemented JPEG display".to_string(),
    };

    values = values.into_iter().map(value_to_str).collect();

    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
               name={attribute_schema.name.clone()}
               attribute_type={attribute_schema.attribute_type}
               values={values}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
                name={attribute_schema.name.clone()}
                attribute_type={attribute_schema.attribute_type}
                value={values.first().cloned().unwrap_or_default()}
            />
        }
    }
}

fn get_custom_attribute_static(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
) -> Html {
    let values = user_attributes
        .iter()
        .find(|a| a.name == attribute_schema.name)
        .map(|attribute| attribute.value.clone())
        .unwrap_or_default();
    let value_to_str = match attribute_schema.attribute_type {
        AttributeType::String | AttributeType::Integer => |v: String| v,
        AttributeType::DateTime => |v: String| {
            console!(format!("Parsing date: {}", &v));
            chrono::DateTime::parse_from_rfc3339(&v)
                .map(|dt| dt.with_timezone(&chrono::offset::Local).naive_local().to_string())
                .unwrap_or_else(|_| "Invalid date".to_string())
        },
        AttributeType::JpegPhoto => |_: String| "Unimplemented JPEG display".to_string(),
    };
    html! {
        <StaticValue label={attribute_schema.name.clone()} id={attribute_schema.name.clone()}>
            {values.into_iter().map(|x| html!{<div>{value_to_str(x)}</div>}).collect::<Vec<_>>()}
        </StaticValue>
    }
}

impl UserDetailsForm {
    fn submit_user_update_form(&mut self, ctx: &Context<Self>) -> Result<bool> {
        // TODO: Handle unloaded files.
        // if let Some(JsFile {
        //     file: Some(_),
        //     contents: None,
        // }) = &self.avatar
        // {
        //     bail!("Image file hasn't finished loading, try again");
        // }
        let mut all_values = read_all_form_attributes(
            ctx.props().user_attributes_schema.iter(),
            &self.form_ref,
            IsAdmin(ctx.props().is_admin),
            EmailIsRequired(!ctx.props().is_edited_user_admin),
        )?;
        let base_attributes = &self.user.attributes;
        all_values.retain(|a| {
            let base_val = base_attributes
                .iter()
                .find(|base_val| base_val.name == a.name);
            base_val
                .map(|v| v.value != a.values)
                .unwrap_or(!a.values.is_empty())
        });
        let remove_attributes: Option<Vec<String>> = if all_values.is_empty() {
            None
        } else {
            Some(all_values.iter().map(|a| a.name.clone()).collect())
        };
        let insert_attributes: Option<Vec<update_user::AttributeValueInput>> =
            if remove_attributes.is_none() {
                None
            } else {
                Some(
                    all_values
                        .into_iter()
                        .filter(|a| !a.values.is_empty())
                        .map(
                            |AttributeValue { name, values }| update_user::AttributeValueInput {
                                name,
                                value: values,
                            },
                        )
                        .collect(),
                )
            };
        let mut user_input = update_user::UpdateUserInput {
            id: self.user.id.clone(),
            email: None,
            displayName: None,
            firstName: None,
            lastName: None,
            avatar: None,
            removeAttributes: None,
            insertAttributes: None,
        };
        let default_user_input = user_input.clone();
        user_input.removeAttributes = remove_attributes;
        user_input.insertAttributes = insert_attributes;
        // Nothing changed.
        if user_input == default_user_input {
            return Ok(false);
        }
        let req = update_user::Variables { user: user_input };
        self.common.call_graphql::<UpdateUser, _>(
            ctx,
            req,
            Msg::UserUpdated,
            "Error trying to update user",
        );
        Ok(false)
    }
}
