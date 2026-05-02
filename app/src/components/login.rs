use crate::{
    components::{
        form::submit::Submit,
        router::{AppRoute, Link},
    },
    infra::{
        api::{HostService, LoginStartError},
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use gloo_console::{error, warn};
use lldap_auth::*;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;

pub struct LoginForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    refreshing: bool,
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
    pub on_logged_in: Callback<(String, bool)>,
    pub password_reset_enabled: bool,
}

/// State carried into `Msg::AuthenticationStartResponse`. The username and
/// password are kept around so we can fall back to the v0.7 login flow on
/// HTTP 409 from the v4.0 endpoint.
pub struct AuthStart {
    pub state: opaque::client::login::ClientLogin,
    pub username: String,
    pub password: String,
    pub response: core::result::Result<Box<login::ServerLoginStartResponse>, LoginStartError>,
}

/// State for the start of the v0.7 (opaque-ke 0.7) login fallback. The
/// password is still required so it can be re-registered in the v4.0 format
/// after a successful v0.7 login.
pub struct V07AuthStart {
    pub state: lldap_auth::v07::V07ClientLoginState,
    pub username: String,
    pub password: String,
    pub response: Result<Box<login_base64::ServerLoginStartResponse>>,
}

/// State for the finish of the v0.7 login. The password is forwarded so
/// the silent v4.0 re-registration can run with it once the JWT cookies
/// are set.
pub struct V07AuthFinish {
    pub username: String,
    pub password: String,
    pub response: Result<(String, bool)>,
}

/// State for the silent password upgrade that runs immediately after a
/// successful v0.7 login. `is_admin` is threaded through so the final
/// `on_logged_in` callback receives the same auth state regardless of
/// whether the upgrade succeeded.
pub struct PasswordUpgradeStart {
    pub state: opaque::client::registration::ClientRegistration,
    pub username: String,
    pub password: String,
    pub is_admin: bool,
    pub response: Result<Box<registration::ServerRegistrationStartResponse>>,
}

/// Final state of the upgrade flow. Even if the response is `Err`, the
/// login itself already succeeded — the upgrade is best-effort and is
/// retried on the next login.
pub struct PasswordUpgradeFinish {
    pub username: String,
    pub is_admin: bool,
    pub response: Result<()>,
}

pub enum Msg {
    Update,
    Submit,
    AuthenticationRefreshResponse(Result<(String, bool)>),
    AuthenticationStartResponse(Box<AuthStart>),
    AuthenticationFinishResponse(Result<(String, bool)>),
    /// Opaque-ke 0.7 fallback flow triggered by HTTP 409 on v4.0 login.
    V07AuthStartResponse(V07AuthStart),
    V07AuthFinishResponse(V07AuthFinish),
    /// After v0.7 login succeeds, silently upgrade the password to v4.0.
    PasswordUpgradeStartResponse(PasswordUpgradeStart),
    PasswordUpgradeFinishResponse(PasswordUpgradeFinish),
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
                let FormModel { username, password } = self.form.model();
                let mut rng = rand::rngs::OsRng;
                let opaque::client::login::ClientLoginStartResult { state, message } =
                    opaque::client::login::start_login(&password, &mut rng)
                        .context("Could not initialize login")?;
                let req = login::ClientLoginStartRequest {
                    username: username.clone().into(),
                    login_start_request: message,
                };
                let password_clone = password.clone();
                let username_clone = username.clone();
                self.common
                    .call_backend(ctx, HostService::login_start(req), move |r| {
                        Msg::AuthenticationStartResponse(Box::new(AuthStart {
                            state,
                            username: username_clone,
                            password: password_clone,
                            response: r,
                        }))
                    });
                Ok(true)
            }
            Msg::AuthenticationStartResponse(boxed) => {
                let AuthStart {
                    state: login_start,
                    username,
                    password,
                    response: res,
                } = *boxed;
                match res {
                    Ok(res) => {
                        let mut rng = rand::rngs::OsRng;
                        let login_finish = match opaque::client::login::finish_login(
                            login_start,
                            res.credential_response,
                            &password,
                            &mut rng,
                        ) {
                            Err(e) => {
                                error!(&format!("Invalid username or password: {}", e));
                                self.common.error = Some(anyhow!("Invalid username or password"));
                                return Ok(true);
                            }
                            Ok(l) => l,
                        };
                        let req = login::ClientLoginFinishRequest {
                            server_data: res.server_data,
                            credential_finalization: login_finish.message,
                        };
                        self.common.call_backend(
                            ctx,
                            HostService::login_finish(req),
                            Msg::AuthenticationFinishResponse,
                        );
                        Ok(false)
                    }
                    Err(LoginStartError::OpaqueV07Version) => {
                        // User has a v0.7 password — fall back to the
                        // v0.7 login flow, then silently re-register as v4.0.
                        let (v07_state, v07_bytes) =
                            match lldap_auth::v07::client_login_start(&password) {
                                Ok(r) => r,
                                Err(e) => {
                                    error!(&format!("v0.7 OPAQUE start failed: {}", e));
                                    self.common.error = Some(anyhow!("Could not start v0.7 login"));
                                    return Ok(true);
                                }
                            };
                        let req = login_base64::ClientLoginStartRequest {
                            username: username.clone().into(),
                            login_start_request: base64::engine::general_purpose::STANDARD
                                .encode(&v07_bytes),
                        };
                        let password_clone = password.clone();
                        self.common.call_backend(
                            ctx,
                            HostService::login_start_v07(req),
                            move |r| {
                                Msg::V07AuthStartResponse(V07AuthStart {
                                    state: v07_state,
                                    username,
                                    password: password_clone,
                                    response: r,
                                })
                            },
                        );
                        Ok(false)
                    }
                    Err(LoginStartError::Other(e)) => {
                        Err(e.context("Could not log in (invalid response to login start)"))
                    }
                }
            }
            Msg::AuthenticationFinishResponse(user_info) => {
                ctx.props()
                    .on_logged_in
                    .emit(user_info.context("Could not log in")?);
                Ok(true)
            }
            Msg::V07AuthStartResponse(V07AuthStart {
                state: v07_state,
                username,
                password,
                response: res,
            }) => {
                let res = res.context("Could not start v0.7 login")?;
                let server_response_bytes = match base64::engine::general_purpose::STANDARD
                    .decode(&res.credential_response)
                {
                    Ok(b) => b,
                    Err(e) => {
                        error!(&format!("Could not decode v0.7 server response: {}", e));
                        self.common.error = Some(anyhow!("Invalid server response to v0.7 login"));
                        return Ok(true);
                    }
                };
                let finalization_bytes =
                    match lldap_auth::v07::client_login_finish(v07_state, &server_response_bytes) {
                        Ok(b) => b,
                        Err(e) => {
                            error!(&format!("Invalid username or password: {}", e));
                            self.common.error = Some(anyhow!("Invalid username or password"));
                            return Ok(true);
                        }
                    };
                let req = login_base64::ClientLoginFinishRequest {
                    server_data: res.server_data,
                    credential_finalization: base64::engine::general_purpose::STANDARD
                        .encode(&finalization_bytes),
                };
                self.common
                    .call_backend(ctx, HostService::login_finish_v07(req), move |r| {
                        Msg::V07AuthFinishResponse(V07AuthFinish {
                            username,
                            password,
                            response: r,
                        })
                    });
                Ok(false)
            }
            Msg::V07AuthFinishResponse(V07AuthFinish {
                username,
                password,
                response: res,
            }) => {
                let (_logged_in_user, is_admin) = res.context("Could not finish v0.7 login")?;
                // v0.7 login succeeded — the JWT cookies are set and the
                // user is effectively logged in. Now silently upgrade the
                // password to v4.0. If this fails, we still report success.
                let mut rng = rand::rngs::OsRng;
                let registration_start = match opaque::client::registration::start_registration(
                    password.as_bytes(),
                    &mut rng,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(&format!(
                            "Could not start password upgrade (login still succeeded): {}",
                            e
                        ));
                        ctx.props().on_logged_in.emit((username, is_admin));
                        return Ok(true);
                    }
                };
                let req = registration::ClientRegistrationStartRequest {
                    username: username.clone().into(),
                    registration_start_request: registration_start.message,
                };
                let password_clone = password.clone();
                self.common
                    .call_backend(ctx, HostService::register_start(req), move |r| {
                        Msg::PasswordUpgradeStartResponse(PasswordUpgradeStart {
                            state: registration_start.state,
                            username,
                            password: password_clone,
                            is_admin,
                            response: r,
                        })
                    });
                Ok(false)
            }
            Msg::PasswordUpgradeStartResponse(PasswordUpgradeStart {
                state: reg_state,
                username,
                password,
                is_admin,
                response: res,
            }) => match res {
                Ok(res) => {
                    let mut rng = rand::rngs::OsRng;
                    let reg_finish = match opaque::client::registration::finish_registration(
                        reg_state,
                        res.registration_response,
                        password.as_bytes(),
                        &mut rng,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(&format!(
                                "Password upgrade finish failed (login still succeeded): {}",
                                e
                            ));
                            ctx.props().on_logged_in.emit((username, is_admin));
                            return Ok(true);
                        }
                    };
                    let req = registration::ClientRegistrationFinishRequest {
                        server_data: res.server_data,
                        registration_upload: reg_finish.message,
                    };
                    self.common
                        .call_backend(ctx, HostService::register_finish(req), move |r| {
                            Msg::PasswordUpgradeFinishResponse(PasswordUpgradeFinish {
                                username,
                                is_admin,
                                response: r,
                            })
                        });
                    Ok(false)
                }
                Err(e) => {
                    warn!(&format!(
                        "Password upgrade register_start failed (login still succeeded): {}",
                        e
                    ));
                    ctx.props().on_logged_in.emit((username, is_admin));
                    Ok(true)
                }
            },
            Msg::PasswordUpgradeFinishResponse(PasswordUpgradeFinish {
                username,
                is_admin,
                response: res,
            }) => {
                if let Err(e) = res {
                    warn!(&format!(
                        "Password upgrade register_finish failed (login still succeeded): {}",
                        e
                    ));
                }
                ctx.props().on_logged_in.emit((username, is_admin));
                Ok(true)
            }
            Msg::AuthenticationRefreshResponse(user_info) => {
                self.refreshing = false;
                if let Ok(user_info) = user_info {
                    ctx.props().on_logged_in.emit(user_info);
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
              </form>
            }
        }
    }
}
