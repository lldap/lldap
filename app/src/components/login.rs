use crate::{
    components::{
        form::submit::Submit,
        router::{AppRoute, Link},
    },
    infra::{
        api::{HostService, LoginOutcome},
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{Result, anyhow, bail};
use gloo_console::error;
use lldap_auth::*;
use lldap_mfa::{TOTP_CODE_ALREADY_USED, split_totp_suffix};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;

pub struct LoginForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    refreshing: bool,
    totp_code: Option<String>,
    /// Username and full password kept for the single retry when the stripped
    /// attempt fails (a real password can end in ":<6 digits>").
    retry_credentials: Option<(String, String)>,
    mfa_help: bool,
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 1, message = "Missing username"))]
    username: String,
    #[validate(length(min = 1, message = "Missing password"))]
    password: String,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_in: Callback<(String, bool, bool)>,
    pub password_reset_enabled: bool,
}

pub enum Msg {
    Update,
    Submit,
    AuthenticationRefreshResponse(Result<(String, bool, bool)>),
    AuthenticationStartResponse(
        (
            opaque::client::login::ClientLogin,
            Result<Box<login::ServerLoginStartResponse>>,
        ),
    ),
    AuthenticationFinishResponse(Result<LoginOutcome>),
}

impl LoginForm {
    fn start_login_attempt(
        &mut self,
        ctx: &Context<Self>,
        username: String,
        password: String,
    ) -> Result<bool> {
        use anyhow::Context;
        let mut rng = rand::rngs::OsRng;
        let opaque::client::login::ClientLoginStartResult { state, message } =
            opaque::client::login::start_login(&password, &mut rng)
                .context("Could not initialize login")?;
        let req = login::ClientLoginStartRequest {
            username: username.into(),
            login_start_request: message,
        };
        self.common
            .call_backend(ctx, HostService::login_start(req), move |r| {
                Msg::AuthenticationStartResponse((state, r))
            });
        Ok(true)
    }
}

impl CommonComponent<LoginForm> for LoginForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        use anyhow::Context;
        match msg {
            Msg::Update => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                self.mfa_help = false;
                let FormModel { username, password } = self.form.model();
                let split = split_totp_suffix(&password).map(|(p, c)| (p.to_owned(), c.to_owned()));
                let password = match split {
                    Some((stripped, code)) => {
                        self.totp_code = Some(code);
                        self.retry_credentials = Some((username.clone(), password));
                        stripped
                    }
                    None => {
                        self.totp_code = None;
                        self.retry_credentials = None;
                        password
                    }
                };
                self.start_login_attempt(ctx, username, password)
            }
            Msg::AuthenticationStartResponse((login_start, res)) => {
                let res = res.context("Could not log in (invalid response to login start)")?;
                let login_finish =
                    match opaque::client::login::finish_login(login_start, res.credential_response)
                    {
                        Err(e) => {
                            if let Some((username, password)) = self.retry_credentials.take() {
                                self.totp_code = None;
                                return self.start_login_attempt(ctx, username, password);
                            }
                            // Common error, we want to print a full error to the console but only a
                            // simple one to the user.
                            error!(&format!("Invalid username or password: {}", e));
                            self.common.error = Some(anyhow!("Invalid username or password"));
                            return Ok(true);
                        }
                        Ok(l) => l,
                    };
                let req = login::ClientLoginFinishRequest {
                    server_data: res.server_data,
                    credential_finalization: login_finish.message,
                    totp_code: self.totp_code.clone(),
                };
                self.common.call_backend(
                    ctx,
                    HostService::login_finish(req),
                    Msg::AuthenticationFinishResponse,
                );
                Ok(false)
            }
            Msg::AuthenticationFinishResponse(res) => {
                // The password was proven client-side: no retry past this point.
                self.retry_credentials = None;
                match res {
                    Err(e) => {
                        if self.totp_code.take().is_some() {
                            error!(&format!("Invalid credentials: {}", e));
                            // Only a replayed code is named: the password was verified first.
                            self.common.error =
                                Some(if e.to_string().contains(TOTP_CODE_ALREADY_USED) {
                                    anyhow!("That code was already used. Wait for the next one.")
                                } else {
                                    anyhow!("Invalid username or password")
                                });
                            Ok(true)
                        } else {
                            Err(e).context("Could not log in")
                        }
                    }
                    Ok(LoginOutcome::MfaRequired) => {
                        self.totp_code = None;
                        self.mfa_help = true;
                        Ok(true)
                    }
                    Ok(LoginOutcome::Success {
                        user_id,
                        is_admin,
                        mfa_enrollment_required,
                    }) => {
                        self.totp_code = None;
                        ctx.props()
                            .on_logged_in
                            .emit((user_id, is_admin, mfa_enrollment_required));
                        Ok(true)
                    }
                }
            }
            Msg::AuthenticationRefreshResponse(user_info) => {
                self.refreshing = false;
                if let Ok((user_id, is_admin, mfa_enrollment_required)) = user_info {
                    ctx.props()
                        .on_logged_in
                        .emit((user_id, is_admin, mfa_enrollment_required));
                }
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for LoginForm {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut app = LoginForm {
            common: CommonComponentParts::<Self>::create(),
            form: Form::<FormModel>::new(FormModel::default()),
            refreshing: true,
            totp_code: None,
            retry_credentials: None,
            mfa_help: false,
        };
        app.common.call_backend(
            ctx,
            HostService::refresh(),
            Msg::AuthenticationRefreshResponse,
        );
        app
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<FormModel>;
        let password_reset_enabled = ctx.props().password_reset_enabled;
        let link = &ctx.link();
        if self.refreshing {
            html! {
              <div>
                <img src={"spinner.gif"} alt={"Loading"} />
              </div>
            }
        } else {
            html! {
              <form class="form center-block col-sm-4 col-offset-4">
                <div class="input-group">
                  <div class="input-group-prepend">
                    <span class="input-group-text">
                      <i class="bi-person-fill"/>
                    </span>
                  </div>
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form={&self.form}
                    field_name="username"
                    placeholder="Username"
                    autocomplete="username"
                    oninput={link.callback(|_| Msg::Update)} />
                </div>
                <div class="input-group">
                  <div class="input-group-prepend">
                    <span class="input-group-text">
                      <i class="bi-lock-fill"/>
                    </span>
                  </div>
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form={&self.form}
                    field_name="password"
                    input_type="password"
                    placeholder="Password"
                    autocomplete="current-password" />
                </div>
                <Submit
                  text="Login"
                  disabled={self.common.is_task_running()}
                  onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}>
                  { if password_reset_enabled {
                    html! {
                      <Link
                        classes="btn-link btn"
                        disabled={self.common.is_task_running()}
                        to={AppRoute::StartResetPassword}>
                        {"Forgot your password?"}
                      </Link>
                    }
                  } else {
                    html!{}
                  }}
                </Submit>
                <div class="form-group">
                { if let Some(e) = &self.common.error {
                    html! { e.to_string() }
                  } else { html! {} }
                }
                </div>
                { if self.mfa_help {
                  html! {
                    <div class="alert alert-warning">
                      <h6 class="fw-bold">
                        <i class="bi-shield-lock me-2"></i>
                        {"This account uses two-factor authentication"}
                      </h6>
                      <p class="mb-2">
                        {"Enter your password, ':' and the current code: "}
                        <code>{"yourpassword:123456"}</code>
                      </p>
                    </div>
                  }
                } else {
                  html!{}
                }}
              </form>
            }
        }
    }
}
