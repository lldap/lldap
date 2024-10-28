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
        api::HostService,
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
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_attributes_schema.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserAttributesSchema;

use get_user_attributes_schema::ResponseData;

pub type Attribute = get_user_attributes_schema::GetUserAttributesSchemaSchemaUserSchemaAttributes;

convert_attribute_type!(get_user_attributes_schema::AttributeType);

impl From<&Attribute> for GraphQlAttributeSchema {
    fn from(attr: &Attribute) -> Self {
        Self {
            name: attr.name.clone(),
            is_list: attr.is_list,
            is_readonly: attr.is_readonly,
            is_editable: attr.is_editable,
        }
    }
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateUser;

pub struct CreateUserForm {
    common: CommonComponentParts<Self>,
    form: yew_form::Form<CreateUserModel>,
    attributes_schema: Option<Vec<Attribute>>,
    form_ref: NodeRef,
}

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct CreateUserModel {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(custom(
        function = "empty_or_long",
        message = "Password should be longer than 8 characters (or left empty)"
    ))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

fn empty_or_long(value: &str) -> Result<(), validator::ValidationError> {
    if value.is_empty() || value.len() >= 8 {
        Ok(())
    } else {
        Err(validator::ValidationError::new(""))
    }
}

pub enum Msg {
    Update,
    ListAttributesResponse(Result<ResponseData>),
    SubmitForm,
    CreateUserResponse(Result<create_user::ResponseData>),
    SuccessfulCreation,
    RegistrationStartResponse(
        (
            opaque::client::registration::ClientRegistration,
            Result<Box<registration::ServerRegistrationStartResponse>>,
        ),
    ),
    RegistrationFinishResponse(Result<()>),
}

impl CommonComponent<CreateUserForm> for CreateUserForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::ListAttributesResponse(schema) => {
                self.attributes_schema =
                    Some(schema?.schema.user_schema.attributes.into_iter().collect());
                Ok(true)
            }
            Msg::SubmitForm => {
                ensure!(self.form.validate(), "Check the form for errors");

                let all_values = read_all_form_attributes(
                    self.attributes_schema.iter().flatten(),
                    &self.form_ref,
                    IsAdmin(true),
                    EmailIsRequired(true),
                )?;
                let attributes = Some(
                    all_values
                        .into_iter()
                        .filter(|a| !a.values.is_empty())
                        .map(
                            |AttributeValue { name, values }| create_user::AttributeValueInput {
                                name,
                                value: values,
                            },
                        )
                        .collect(),
                );

                let model = self.form.model();
                let req = create_user::Variables {
                    user: create_user::CreateUserInput {
                        id: model.username,
                        email: None,
                        displayName: None,
                        firstName: None,
                        lastName: None,
                        avatar: None,
                        attributes,
                    },
                };
                self.common.call_graphql::<CreateUser, _>(
                    ctx,
                    req,
                    Msg::CreateUserResponse,
                    "Error trying to create user",
                );
                Ok(true)
            }
            Msg::CreateUserResponse(r) => {
                match r {
                    Err(e) => return Err(e),
                    Ok(r) => log!(&format!(
                        "Created user '{}' at '{}'",
                        &r.create_user.id, &r.create_user.creation_date
                    )),
                };
                let model = self.form.model();
                let user_id = model.username;
                let password = model.password;
                if !password.is_empty() {
                    // User was successfully created, let's register the password.
                    let mut rng = rand::rngs::OsRng;
                    let opaque::client::registration::ClientRegistrationStartResult {
                        state,
                        message,
                    } = opaque::client::registration::start_registration(
                        password.as_bytes(),
                        &mut rng,
                    )?;
                    let req = registration::ClientRegistrationStartRequest {
                        username: user_id.into(),
                        registration_start_request: message,
                    };
                    self.common
                        .call_backend(ctx, HostService::register_start(req), move |r| {
                            Msg::RegistrationStartResponse((state, r))
                        });
                } else {
                    self.update(ctx, Msg::SuccessfulCreation);
                }
                Ok(false)
            }
            Msg::RegistrationStartResponse((registration_start, response)) => {
                let response = response?;
                let mut rng = rand::rngs::OsRng;
                let registration_upload = opaque::client::registration::finish_registration(
                    registration_start,
                    response.registration_response,
                    &mut rng,
                )?;
                let req = registration::ClientRegistrationFinishRequest {
                    server_data: response.server_data,
                    registration_upload: registration_upload.message,
                };
                self.common.call_backend(
                    ctx,
                    HostService::register_finish(req),
                    Msg::RegistrationFinishResponse,
                );
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                response?;
                self.handle_msg(ctx, Msg::SuccessfulCreation)
            }
            Msg::SuccessfulCreation => {
                ctx.link().history().unwrap().push(AppRoute::ListUsers);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for CreateUserForm {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = Self {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<CreateUserModel>::new(CreateUserModel::default()),
            attributes_schema: None,
            form_ref: NodeRef::default(),
        };
        component.common.call_graphql::<GetUserAttributesSchema, _>(
            ctx,
            get_user_attributes_schema::Variables {},
            Msg::ListAttributesResponse,
            "Error trying to fetch user schema",
        );
        component
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <div class="row justify-content-center">
            <form class="form py-3"
              ref={self.form_ref.clone()}>
              <Field<CreateUserModel>
                form={&self.form}
                required=true
                label="User name"
                field_name="username"
                oninput={link.callback(|_| Msg::Update)} />
              {
                  self.attributes_schema
                      .iter()
                      .flatten()
                      .filter(|a| !a.is_readonly)
                      .map(get_custom_attribute_input)
                      .collect::<Vec<_>>()
              }
              <Field<CreateUserModel>
                form={&self.form}
                label="Password"
                field_name="password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::Update)} />
              <Field<CreateUserModel>
                form={&self.form}
                label="Confirm password"
                field_name="confirm_password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::Update)} />
              <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})} />
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
