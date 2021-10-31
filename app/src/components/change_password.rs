use crate::{
    components::router::{AppRoute, NavButton},
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{anyhow, bail, Context, Result};
use lldap_auth::*;
use validator_derive::Validate;
use yew::{prelude::*, services::ConsoleService};
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
};

#[derive(PartialEq, Eq)]
enum OpaqueData {
    None,
    Login(opaque::client::login::ClientLogin),
    Registration(opaque::client::registration::ClientRegistration),
}

impl Default for OpaqueData {
    fn default() -> Self {
        OpaqueData::None
    }
}

impl OpaqueData {
    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Clone, Default)]
pub struct FormModel {
    #[validate(custom(
        function = "empty_or_long",
        message = "Password should be longer than 8 characters"
    ))]
    old_password: String,
    #[validate(length(min = 8, message = "Invalid password. Min length: 8"))]
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

pub struct ChangePasswordForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    opaque_data: OpaqueData,
    route_dispatcher: RouteAgentDispatcher,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
}

pub enum Msg {
    FormUpdate,
    Submit,
    AuthenticationStartResponse(Result<Box<login::ServerLoginStartResponse>>),
    SubmitNewPassword,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
}

impl CommonComponent<ChangePasswordForm> for ChangePasswordForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                if self.common.is_admin {
                    self.handle_msg(Msg::SubmitNewPassword)
                } else {
                    let old_password = self.form.model().old_password;
                    if old_password.is_empty() {
                        bail!("Current password should not be empty");
                    }
                    let mut rng = rand::rngs::OsRng;
                    let login_start_request =
                        opaque::client::login::start_login(&old_password, &mut rng)
                            .context("Could not initialize login")?;
                    self.opaque_data = OpaqueData::Login(login_start_request.state);
                    let req = login::ClientLoginStartRequest {
                        username: self.common.username.clone(),
                        login_start_request: login_start_request.message,
                    };
                    self.common.call_backend(
                        HostService::login_start,
                        req,
                        Msg::AuthenticationStartResponse,
                    )?;
                    Ok(true)
                }
            }
            Msg::AuthenticationStartResponse(res) => {
                let res = res.context("Could not initiate login")?;
                match self.opaque_data.take() {
                    OpaqueData::Login(l) => {
                        opaque::client::login::finish_login(l, res.credential_response).map_err(
                            |e| {
                                // Common error, we want to print a full error to the console but only a
                                // simple one to the user.
                                ConsoleService::error(&format!(
                                    "Invalid username or password: {}",
                                    e
                                ));
                                anyhow!("Invalid username or password")
                            },
                        )?;
                    }
                    _ => panic!("Unexpected data in opaque_data field"),
                };
                self.handle_msg(Msg::SubmitNewPassword)
            }
            Msg::SubmitNewPassword => {
                let mut rng = rand::rngs::OsRng;
                let new_password = self.form.model().password;
                let registration_start_request =
                    opaque::client::registration::start_registration(&new_password, &mut rng)
                        .context("Could not initiate password change")?;
                let req = registration::ClientRegistrationStartRequest {
                    username: self.common.username.clone(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = OpaqueData::Registration(registration_start_request.state);
                self.common.call_backend(
                    HostService::register_start,
                    req,
                    Msg::RegistrationStartResponse,
                )?;
                Ok(true)
            }
            Msg::RegistrationStartResponse(res) => {
                let res = res.context("Could not initiate password change")?;
                match self.opaque_data.take() {
                    OpaqueData::Registration(registration) => {
                        let mut rng = rand::rngs::OsRng;
                        let registration_finish =
                            opaque::client::registration::finish_registration(
                                registration,
                                res.registration_response,
                                &mut rng,
                            )
                            .context("Error during password change")?;
                        let req = registration::ClientRegistrationFinishRequest {
                            server_data: res.server_data,
                            registration_upload: registration_finish.message,
                        };
                        self.common.call_backend(
                            HostService::register_finish,
                            req,
                            Msg::RegistrationFinishResponse,
                        )
                    }
                    _ => panic!("Unexpected data in opaque_data field"),
                }?;
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                self.common.cancel_task();
                if response.is_ok() {
                    self.route_dispatcher
                        .send(RouteRequest::ChangeRoute(Route::from(
                            AppRoute::UserDetails(self.common.username.clone()),
                        )));
                }
                response?;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ChangePasswordForm {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        ChangePasswordForm {
            common: CommonComponentParts::<Self>::create(props, link),
            form: yew_form::Form::<FormModel>::new(FormModel::default()),
            opaque_data: OpaqueData::None,
            route_dispatcher: RouteAgentDispatcher::new(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        let is_admin = self.common.is_admin;
        type Field = yew_form::Field<FormModel>;
        html! {
          <>
            <form
              class="form">
              {if !is_admin { html! {
                <div class="form-group row">
                  <label for="old_password"
                    class="form-label col-sm-2 col-form-label">
                    {"Current password*:"}
                  </label>
                  <div class="col-sm-10">
                    <Field
                      form=&self.form
                      field_name="old_password"
                      class="form-control"
                      class_invalid="is-invalid has-error"
                      class_valid="has-success"
                      autocomplete="current-password"
                      oninput=self.common.callback(|_| Msg::FormUpdate) />
                    <div class="invalid-feedback">
                      {&self.form.field_message("old_password")}
                    </div>
                  </div>
                </div>
              }} else { html! {} }}
              <div class="form-group row">
                <label for="new_password"
                  class="form-label col-sm-2 col-form-label">
                  {"New password*:"}
                </label>
                <div class="col-sm-10">
                  <Field
                    form=&self.form
                    field_name="password"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="new-password"
                    oninput=self.common.callback(|_| Msg::FormUpdate) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("password")}
                  </div>
                </div>
              </div>
              <div class="form-group row">
                <label for="confirm_password"
                  class="form-label col-sm-2 col-form-label">
                  {"Confirm password*:"}
                </label>
                <div class="col-sm-10">
                  <Field
                    form=&self.form
                    field_name="confirm_password"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="new-password"
                    oninput=self.common.callback(|_| Msg::FormUpdate) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("confirm_password")}
                  </div>
                </div>
              </div>
              <div class="form-group row">
                <button
                  class="btn btn-primary col-sm-1 col-form-label"
                  type="submit"
                  disabled=self.common.is_task_running()
                  onclick=self.common.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})>
                  {"Submit"}
                </button>
              </div>
            </form>
            { if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            <div>
              <NavButton
                classes="btn btn-primary"
                route=AppRoute::UserDetails(self.common.username.clone())>
                {"Back"}
              </NavButton>
            </div>
          </>
        }
    }
}
