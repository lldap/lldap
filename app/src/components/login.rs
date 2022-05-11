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

pub struct LoginForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    refreshing: bool,
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 1, message = "Missing username"))]
    username: String,
    #[validate(length(min = 8, message = "Invalid password. Min length: 8"))]
    password: String,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_in: Callback<(String, bool)>,
}

pub enum Msg {
    Update,
    Submit,
    AuthenticationRefreshResponse(Result<(String, bool)>),
    AuthenticationStartResponse(
        (
            opaque::client::login::ClientLogin,
            Result<Box<login::ServerLoginStartResponse>>,
        ),
    ),
    AuthenticationFinishResponse(Result<(String, bool)>),
}

impl CommonComponent<LoginForm> for LoginForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
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
                    username,
                    login_start_request: message,
                };
                self.common
                    .call_backend(HostService::login_start, req, move |r| {
                        Msg::AuthenticationStartResponse((state, r))
                    })?;
                Ok(true)
            }
            Msg::AuthenticationStartResponse((login_start, res)) => {
                let res = res.context("Could not log in (invalid response to login start)")?;
                let login_finish =
                    match opaque::client::login::finish_login(login_start, res.credential_response)
                    {
                        Err(e) => {
                            // Common error, we want to print a full error to the console but only a
                            // simple one to the user.
                            ConsoleService::error(&format!("Invalid username or password: {}", e));
                            self.common.error = Some(anyhow!("Invalid username or password"));
                            self.common.cancel_task();
                            return Ok(true);
                        }
                        Ok(l) => l,
                    };
                let req = login::ClientLoginFinishRequest {
                    server_data: res.server_data,
                    credential_finalization: login_finish.message,
                };
                self.common.call_backend(
                    HostService::login_finish,
                    req,
                    Msg::AuthenticationFinishResponse,
                )?;
                Ok(false)
            }
            Msg::AuthenticationFinishResponse(user_info) => {
                self.common.cancel_task();
                self.common
                    .on_logged_in
                    .emit(user_info.context("Could not log in")?);
                Ok(true)
            }
            Msg::AuthenticationRefreshResponse(user_info) => {
                self.refreshing = false;
                self.common.cancel_task();
                if let Ok(user_info) = user_info {
                    self.common.on_logged_in.emit(user_info);
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

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut app = LoginForm {
            common: CommonComponentParts::<Self>::create(props, link),
            form: Form::<FormModel>::new(FormModel::default()),
            refreshing: true,
        };
        if let Err(e) =
            app.common
                .call_backend(HostService::refresh, (), Msg::AuthenticationRefreshResponse)
        {
            ConsoleService::debug(&format!("Could not refresh auth: {}", e));
            app.refreshing = false;
        }
        app
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        type Field = yew_form::Field<FormModel>;
        if self.refreshing {
            html! {
              <div>
                <img src={"spinner.gif"} alt={"Loading"} />
              </div>
            }
        } else {
            html! {
              <form
                class="form center-block col-sm-4 col-offset-4">
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
                      form=&self.form
                      field_name="username"
                      placeholder="Username"
                      autocomplete="username"
                      oninput=self.common.callback(|_| Msg::Update) />
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
                      form=&self.form
                      field_name="password"
                      input_type="password"
                      placeholder="Password"
                      autocomplete="current-password" />
                  </div>
                  <div class="form-group mt-3">
                    <button
                      type="submit"
                      class="btn btn-primary"
                      disabled=self.common.is_task_running()
                      onclick=self.common.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})>
                      {"Login"}
                    </button>
                    <NavButton
                      classes="btn-link btn"
                      disabled=self.common.is_task_running()
                      route=AppRoute::StartResetPassword>
                      {"Forgot your password?"}
                    </NavButton>
                  </div>
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
