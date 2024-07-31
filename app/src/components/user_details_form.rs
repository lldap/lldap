use crate::{
    components::{
        form::{
            attribute_input::{ListAttributeInput, SingleAttributeInput},
            field::Field, static_value::StaticValue, submit::Submit,
        },
        user_details::{Attribute, AttributeSchema, User},
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        schema::AttributeType,
    },
};
use anyhow::{anyhow, bail, Ok, Result};
use gloo_console::log;
use graphql_client::GraphQLQuery;
use validator::HasLen;
use validator_derive::Validate;
use web_sys::{FormData, HtmlFormElement};
use yew::prelude::*;
use yew_form_derive::Model;

/// The fields of the form, with the editable details and the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone)]
pub struct UserModel {
    #[validate(email)]
    email: String,
    display_name: String,
}

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
    form: yew_form::Form<UserModel>,
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
            Msg::UserUpdated(response) => self.user_update_finished(response),
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
        let model = UserModel {
            email: ctx.props().user.email.clone(),
            display_name: ctx.props().user.display_name.clone(),
        };
        Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::new(model),
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

        html! {
          <div class="py-3">
            <form
              class="form"
              ref={self.form_ref.clone()}>
              <StaticValue label="User ID" id="userId">
                <i>{&self.user.id}</i>
              </StaticValue>
              <StaticValue label="Creation date" id="creationDate">
                {&self.user.creation_date.naive_local().date()}
              </StaticValue>
              <StaticValue label="UUID" id="uuid">
                {&self.user.uuid}
              </StaticValue>
              <Field<UserModel>
                form={&self.form}
                required=true
                label="Email"
                field_name="email"
                input_type="email"
                oninput={link.callback(|_| Msg::Update)} />
              <Field<UserModel>
                form={&self.form}
                label="Display name"
                field_name="display_name"
                autocomplete="name"
                oninput={link.callback(|_| Msg::Update)} />
              {ctx.props().user_attributes_schema.iter().filter(|a| a.is_editable).map(|s| get_custom_attribute_input(s, &self.user.attributes)).collect::<Vec<_>>()}
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

type AttributeValue = (String, Vec<String>);

fn get_values_from_form_data(
    schema: Vec<&AttributeSchema>,
    form: &FormData,
) -> Result<Vec<AttributeValue>> {
    schema
        .into_iter()
        .map(|attr| -> Result<AttributeValue> {
            let val = form
                .get_all(attr.name.as_str())
                .iter()
                .map(|js_val| js_val.as_string().unwrap_or_default())
                .filter(|val| !val.is_empty())
                .collect::<Vec<String>>();
            if val.length() > 1 && !attr.is_list {
                return Err(anyhow!(
                    "Multiple values supplied for non-list attribute {}",
                    attr.name
                ));
            }
            Ok((attr.name.clone(), val))
        })
        .collect()
}

fn get_custom_attribute_input(
    attribute_schema: &AttributeSchema,
    user_attributes: &[Attribute],
) -> Html {
    if attribute_schema.is_list {
        let values = user_attributes
            .iter()
            .find(|a| a.name == attribute_schema.name)
            .map(|attribute| attribute.value.clone())
            .unwrap_or_default();
        html! {<ListAttributeInput name={attribute_schema.name.clone()} attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())} values={values}/>}
    } else {
        let value = user_attributes
            .iter()
            .find(|a| a.name == attribute_schema.name)
            .and_then(|attribute| attribute.value.first().cloned())
            .unwrap_or_default();
        html! {<SingleAttributeInput name={attribute_schema.name.clone()} attribute_type={Into::<AttributeType>::into(attribute_schema.attribute_type.clone())} value={value}/>}
    }
}

impl UserDetailsForm {
    fn submit_user_update_form(&mut self, ctx: &Context<Self>) -> Result<bool> {
        if !self.form.validate() {
            bail!("Invalid inputs");
        }
        // if let Some(JsFile {
        //     file: Some(_),
        //     contents: None,
        // }) = &self.avatar
        // {
        //     bail!("Image file hasn't finished loading, try again");
        // }
        let form = self.form_ref.cast::<HtmlFormElement>().unwrap();
        let form_data = FormData::new_with_form(&form)
            .map_err(|e| anyhow!("Failed to get FormData: {:#?}", e.as_string()))?;
        let mut all_values = get_values_from_form_data(
            ctx.props()
                .user_attributes_schema
                .iter()
                .filter(|attr| attr.is_editable)
                .collect(),
            &form_data,
        )?;
        let base_user = &self.user;
        let base_attributes = &self.user.attributes;
        log!(format!("base_attributes: {:#?}\nall_values: {:#?}", base_attributes, all_values));
        all_values.retain(|(name, val)| {
            let name = name.clone();
            let base_val = base_attributes
                .iter()
                .find(|base_val| base_val.name == name);
            let new_values = val.clone();
            base_val.map(|v| v.value != new_values).unwrap_or(!new_values.is_empty())
        });
        let remove_attributes: Option<Vec<String>> = if all_values.is_empty() {
            None
        } else {
            Some(all_values.iter().map(|(name, _)| name.clone()).collect())
        };
        let insert_attributes: Option<Vec<update_user::AttributeValueInput>> =
            if remove_attributes.is_none() {
                None
            } else {
                Some(
                    all_values
                        .into_iter()
                        .filter(|(_, value)| !value.is_empty())
                        .map(|(name, value)| update_user::AttributeValueInput { name, value })
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
        let model = self.form.model();
        let email = model.email;
        if base_user.email != email {
            user_input.email = Some(email);
        }
        if base_user.display_name != model.display_name {
            user_input.displayName = Some(model.display_name);
        }
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

    fn user_update_finished(&mut self, r: Result<update_user::ResponseData>) -> Result<bool> {
        r?;
        let model = self.form.model();
        self.user.email = model.email;
        self.user.display_name = model.display_name;
        self.just_updated = true;
        Ok(true)
    }
}
