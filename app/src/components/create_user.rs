use crate::{components::router::AppRoute, infra::api::HostService};
use anyhow::{bail, Context, Result};
use graphql_client::GraphQLQuery;
use lldap_auth::{opaque, registration};
use validator_derive::Validate;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};
use yew_form_derive::Model;
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreateUser;

pub struct CreateUserForm {
    link: ComponentLink<Self>,
    route_dispatcher: RouteAgentDispatcher,
    form: yew_form::Form<CreateUserModel>,
    error: Option<anyhow::Error>,
    // Used to keep the request alive long enough.
    task: Option<FetchTask>,
}

#[derive(Model, Validate, PartialEq, Clone, Default)]
pub struct CreateUserModel {
    #[validate(length(min = 1, message = "Username is required"))]
    username: String,
    #[validate(email(message = "A valid email is required"))]
    email: String,
    #[validate(length(min = 1, message = "Display name is required"))]
    display_name: String,
    first_name: String,
    last_name: String,
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

impl CreateUserForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::SubmitForm => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let model = self.form.model();
                let to_option = |s: String| if s.is_empty() { None } else { Some(s) };
                let req = create_user::Variables {
                    user: create_user::CreateUserInput {
                        id: model.username,
                        email: model.email,
                        displayName: to_option(model.display_name),
                        firstName: to_option(model.first_name),
                        lastName: to_option(model.last_name),
                    },
                };
                self.task = Some(HostService::graphql_query::<CreateUser>(
                    req,
                    self.link.callback(Msg::CreateUserResponse),
                    "Error trying to create user",
                )?);
                Ok(true)
            }
            Msg::CreateUserResponse(r) => {
                match r {
                    Err(e) => return Err(e),
                    Ok(r) => ConsoleService::log(&format!(
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
                    } = opaque::client::registration::start_registration(&password, &mut rng)?;
                    let req = registration::ClientRegistrationStartRequest {
                        username: user_id,
                        registration_start_request: message,
                    };
                    self.task = Some(
                        HostService::register_start(
                            req,
                            self.link
                                .callback_once(move |r| Msg::RegistrationStartResponse((state, r))),
                        )
                        .context("Error trying to create user")?,
                    );
                } else {
                    self.update(Msg::SuccessfulCreation);
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
                self.task = Some(
                    HostService::register_finish(
                        req,
                        self.link.callback(Msg::RegistrationFinishResponse),
                    )
                    .context("Error trying to register user")?,
                );
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                response?;
                self.handle_msg(Msg::SuccessfulCreation)
            }
            Msg::SuccessfulCreation => {
                self.route_dispatcher
                    .send(RouteRequest::ChangeRoute(Route::from(AppRoute::ListUsers)));
                Ok(true)
            }
        }
    }
}

impl Component for CreateUserForm {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            route_dispatcher: RouteAgentDispatcher::new(),
            form: yew_form::Form::<CreateUserModel>::new(CreateUserModel::default()),
            error: None,
            task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.error = None;
        match self.handle_msg(msg) {
            Err(e) => {
                ConsoleService::error(&e.to_string());
                self.error = Some(e);
                self.task = None;
                true
            }
            Ok(b) => b,
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        type Field = yew_form::Field<CreateUserModel>;
        html! {
          <div class="row justify-content-center">
            <form class="form shadow-sm py-3" style="max-width: 636px">
              <div class="row mb-3">
                <h5 class="fw-bold">{"Create a user"}</h5>
              </div>
              <div class="form-group row mb-3">
                <label for="username"
                  class="form-label col-4 col-form-label">
                  {"User name*:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    field_name="username"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="username"
                    oninput=self.link.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("username")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="email"
                  class="form-label col-4 col-form-label">
                  {"Email*:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    input_type="email"
                    field_name="email"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="email"
                    oninput=self.link.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("email")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="display-name"
                  class="form-label col-4 col-form-label">
                  {"Display name*:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    autocomplete="name"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    field_name="display_name"
                    oninput=self.link.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("display_name")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="first-name"
                  class="form-label col-4 col-form-label">
                  {"First name:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    autocomplete="given-name"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    field_name="first_name"
                    oninput=self.link.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("first_name")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="last-name"
                  class="form-label col-4 col-form-label">
                  {"Last name:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    autocomplete="family-name"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    field_name="last_name"
                    oninput=self.link.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("last_name")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="password"
                  class="form-label col-4 col-form-label">
                  {"Password:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    input_type="password"
                    field_name="password"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="new-password"
                    oninput=self.link.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("password")}
                  </div>
                </div>
              </div>
              <div class="form-group row mb-3">
                <label for="confirm_password"
                  class="form-label col-4 col-form-label">
                  {"Confirm password:"}
                </label>
                <div class="col-8">
                  <Field
                    form=&self.form
                    input_type="password"
                    field_name="confirm_password"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="new-password"
                    oninput=self.link.callback(|_| Msg::Update) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("confirm_password")}
                  </div>
                </div>
              </div>
              <div class="form-group row justify-content-center">
                <button
                  class="btn btn-primary col-auto col-form-label mt-4"
                  disabled=self.task.is_some()
                  type="submit"
                  onclick=self.link.callback(|e: MouseEvent| {e.prevent_default(); Msg::SubmitForm})>
                  {"Submit"}
                </button>
              </div>
            </form>
            { if let Some(e) = &self.error {
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
