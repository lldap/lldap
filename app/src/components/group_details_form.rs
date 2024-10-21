use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            static_value::StaticValue,
            submit::Submit,
        },
        group_details::{Attribute, AttributeSchema, Group},
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::{read_all_form_attributes, AttributeValue},
        schema::AttributeType,
    },
};
use anyhow::{Ok, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

/// The GraphQL query sent to the server to update the group details.
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/update_group.graphql",
    response_derives = "Debug",
    variables_derives = "Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdateGroup;

/// A [yew::Component] to display the group details, with a form allowing to edit them.
pub struct GroupDetailsForm {
    common: CommonComponentParts<Self>,
    /// True if we just successfully updated the group, to display a success message.
    just_updated: bool,
    updated_group_name: bool,
    group: Group,
    form_ref: NodeRef,
}

pub enum Msg {
    /// A form field changed.
    Update,
    /// The "Submit" button was clicked.
    SubmitClicked,
    /// We got the response from the server about our update message.
    GroupUpdated(Result<update_group::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    /// The current group details.
    pub group: Group,
    pub group_attributes_schema: Vec<AttributeSchema>,
    pub is_admin: bool,
    pub on_display_name_updated: Callback<()>,
}

impl CommonComponent<GroupDetailsForm> for GroupDetailsForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitClicked => self.submit_group_update_form(ctx),
            Msg::GroupUpdated(Err(e)) => Err(e),
            Msg::GroupUpdated(Result::Ok(_)) => {
                self.just_updated = true;
                if self.updated_group_name {
                    self.updated_group_name = false;
                    ctx.props().on_display_name_updated.emit(());
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for GroupDetailsForm {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            just_updated: false,
            updated_group_name: false,
            group: ctx.props().group.clone(),
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
                get_custom_attribute_input(a, &self.group.attributes)
            } else {
                get_custom_attribute_static(a, &self.group.attributes)
            }
        };
        html! {
          <div class="py-3">
            <form
              class="form"
              ref={self.form_ref.clone()}>
              <StaticValue label="Group ID" id="groupId">
                <i>{&self.group.id}</i>
              </StaticValue>
              {
                  ctx
                      .props()
                      .group_attributes_schema
                      .iter()
                      .filter(|a| a.is_hardcoded && a.name != "group_id")
                      .map(display_field)
                      .collect::<Vec<_>>()
              }
              {
                  ctx
                      .props()
                      .group_attributes_schema
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
              <div class="alert alert-success mt-4">{"Group successfully updated!"}</div>
            </div>
          </div>
        }
    }
}

fn get_custom_attribute_input(
    attribute_schema: &AttributeSchema,
    group_attributes: &[Attribute],
) -> Html {
    let values = group_attributes
        .iter()
        .find(|a| a.name == attribute_schema.name)
        .map(|attribute| attribute.value.clone())
        .unwrap_or_default();
    if attribute_schema.is_list {
        html! {
            <ListAttributeInput
               name={attribute_schema.name.clone()}
               attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())}
               values={values}
            />
        }
    } else {
        html! {
            <SingleAttributeInput
                name={attribute_schema.name.clone()}
                attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())}
                value={values.first().cloned().unwrap_or_default()}
            />
        }
    }
}

fn get_custom_attribute_static(
    attribute_schema: &AttributeSchema,
    group_attributes: &[Attribute],
) -> Html {
    let values = group_attributes
        .iter()
        .find(|a| a.name == attribute_schema.name)
        .map(|attribute| attribute.value.clone())
        .unwrap_or_default();
    html! {
        <StaticValue label={attribute_schema.name.clone()} id={attribute_schema.name.clone()}>
            {values.into_iter().map(|x| html!{<div>{x}</div>}).collect::<Vec<_>>()}
        </StaticValue>
    }
}

impl GroupDetailsForm {
    fn submit_group_update_form(&mut self, ctx: &Context<Self>) -> Result<bool> {
        let mut all_values = read_all_form_attributes(
            ctx.props().group_attributes_schema.iter(),
            &self.form_ref,
            ctx.props().is_admin,
            false,
        )?;
        let base_attributes = &self.group.attributes;
        all_values.retain(|a| {
            let base_val = base_attributes
                .iter()
                .find(|base_val| base_val.name == a.name);
            base_val
                .map(|v| v.value != a.values)
                .unwrap_or(!a.values.is_empty())
        });
        if all_values.iter().any(|a| a.name == "display_name") {
            self.updated_group_name = true;
        }
        let remove_attributes: Option<Vec<String>> = if all_values.is_empty() {
            None
        } else {
            Some(all_values.iter().map(|a| a.name.clone()).collect())
        };
        let insert_attributes: Option<Vec<update_group::AttributeValueInput>> =
            if remove_attributes.is_none() {
                None
            } else {
                Some(
                    all_values
                        .into_iter()
                        .filter(|a| !a.values.is_empty())
                        .map(
                            |AttributeValue { name, values }| update_group::AttributeValueInput {
                                name,
                                value: values,
                            },
                        )
                        .collect(),
                )
            };
        let mut group_input = update_group::UpdateGroupInput {
            id: self.group.id,
            displayName: None,
            removeAttributes: None,
            insertAttributes: None,
        };
        let default_group_input = group_input.clone();
        group_input.removeAttributes = remove_attributes;
        group_input.insertAttributes = insert_attributes;
        // Nothing changed.
        if group_input == default_group_input {
            return Ok(false);
        }
        let req = update_group::Variables { group: group_input };
        self.common.call_graphql::<UpdateGroup, _>(
            ctx,
            req,
            Msg::GroupUpdated,
            "Error trying to update group",
        );
        Ok(false)
    }
}
