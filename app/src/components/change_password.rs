use crate::{
    components::{
        form::{field::Field, submit::Submit},
        router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{anyhow, bail, Result};
use gloo_console::error;
use lldap_auth::*;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

use regex::Regex;

#[derive(PartialEq, Eq, Default)]
enum OpaqueData {
    #[default]
    None,
    Login(opaque::client::login::ClientLogin),
    Registration(opaque::client::registration::ClientRegistration),
}

impl OpaqueData {
    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(custom(
        function = "empty_or_long",
        message = "Password should be longer than 8 characters"
    ))]
    old_password: String,

    #[validate(custom(
            function = "validate_password_complexity",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one symbol, and one number"
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

fn validate_password_complexity(value: &str) -> Result<(), validator::ValidationError> {
    let has_uppercase = Regex::new(r"[A-Z]").unwrap().is_match(value);
    let has_lowercase = Regex::new(r"[a-z]").unwrap().is_match(value);
    let has_symbol = Regex::new(r"[^A-Za-z0-9]").unwrap().is_match(value);
    let has_number = Regex::new(r"\d").unwrap().is_match(value);

    if has_uppercase && has_lowercase && has_symbol && has_number {
        Ok(())
    } else {
        Err(validator::ValidationError::new(""))
    }
}

pub struct ChangePasswordForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    opaque_data: OpaqueData,
}

#[derive(Clone, PartialEq, Eq, Properties)]
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
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                if ctx.props().is_admin {
                    self.handle_msg(ctx, Msg::SubmitNewPassword)
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
                        username: ctx.props().username.clone().into(),
                        login_start_request: login_start_request.message,
                    };
                    self.common.call_backend(
                        ctx,
                        HostService::login_start(req),
                        Msg::AuthenticationStartResponse,
                    );
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
                                error!(&format!("Invalid username or password: {}", e));
                                anyhow!("Invalid username or password")
                            },
                        )?;
                    }
                    _ => panic!("Unexpected data in opaque_data field"),
                };
                self.handle_msg(ctx, Msg::SubmitNewPassword)
            }
            Msg::SubmitNewPassword => {
                let mut rng = rand::rngs::OsRng;
                let new_password = self.form.model().password;
                let registration_start_request = opaque::client::registration::start_registration(
                    new_password.as_bytes(),
                    &mut rng,
                )
                .context("Could not initiate password change")?;
                let req = registration::ClientRegistrationStartRequest {
                    username: ctx.props().username.clone().into(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = OpaqueData::Registration(registration_start_request.state);
                self.common.call_backend(
                    ctx,
                    HostService::register_start(req),
                    Msg::RegistrationStartResponse,
                );
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
                            ctx,
                            HostService::register_finish(req),
                            Msg::RegistrationFinishResponse,
                        );
                    }
                    _ => panic!("Unexpected data in opaque_data field"),
                };
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                if response.is_ok() {
                    ctx.link().history().unwrap().push(AppRoute::UserDetails {
                        user_id: ctx.props().username.clone(),
                    });
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

    fn create(_: &Context<Self>) -> Self {
        ChangePasswordForm {
            common: CommonComponentParts::<Self>::create(),
            form: yew_form::Form::<FormModel>::new(FormModel::default()),
            opaque_data: OpaqueData::None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let is_admin = ctx.props().is_admin;
        let link = ctx.link();
        html! {
          <>
            <div class="mb-2 mt-2">
              <h5 class="fw-bold">
                {"Change password"}
              </h5>
            </div>
            {
              if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger mt-3 mb-3">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            <form class="form">
              {if !is_admin { html! {
                <Field<FormModel>
                  form={&self.form}
                  required=true
                  label="Current password"
                  field_name="old_password"
                  input_type="password"
                  autocomplete="current-password"
                  oninput={link.callback(|_| Msg::FormUpdate)} />
              }} else { html! {} }}
              <Field<FormModel>
                form={&self.form}
                required=true
                label="New password"
                field_name="password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::FormUpdate)} />
              <Field<FormModel>
                form={&self.form}
                required=true
                label="Confirm password"
                field_name="confirm_password"
                input_type="password"
                autocomplete="new-password"
                oninput={link.callback(|_| Msg::FormUpdate)} />
              <Submit
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}
                text="Save changes" >
                <Link
                  classes="btn btn-secondary ms-2 col-auto col-form-label"
                  to={AppRoute::UserDetails{user_id: ctx.props().username.clone()}}>
                  <i class="bi-arrow-return-left me-2"></i>
                  {"Back"}
                </Link>
              </Submit>
            </form>
          </>
        }
    }
}
