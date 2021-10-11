use crate::infra::api::HostService;
use anyhow::{anyhow, bail, Context, Result};
use lldap_auth::*;
use validator_derive::Validate;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};
use yew_form::Form;
use yew_form_derive::Model;

pub struct LoginForm {
    link: ComponentLink<Self>,
    on_logged_in: Callback<(String, bool)>,
    error: Option<anyhow::Error>,
    form: Form<FormModel>,
    // Used to keep the request alive long enough.
    task: Option<FetchTask>,
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
    AuthenticationStartResponse(
        (
            opaque::client::login::ClientLogin,
            Result<Box<login::ServerLoginStartResponse>>,
        ),
    ),
    AuthenticationFinishResponse(Result<(String, bool)>),
}

impl LoginForm {
    fn handle_message(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Invalid inputs");
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
                self.task = Some(HostService::login_start(
                    req,
                    self.link
                        .callback_once(move |r| Msg::AuthenticationStartResponse((state, r))),
                )?);
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
                            self.error = Some(anyhow!("Invalid username or password"));
                            return Ok(true);
                        }
                        Ok(l) => l,
                    };
                let req = login::ClientLoginFinishRequest {
                    server_data: res.server_data,
                    credential_finalization: login_finish.message,
                };
                self.task = Some(HostService::login_finish(
                    req,
                    self.link.callback_once(Msg::AuthenticationFinishResponse),
                )?);
                Ok(false)
            }
            Msg::AuthenticationFinishResponse(user_info) => {
                self.task = None;
                self.on_logged_in
                    .emit(user_info.context("Could not log in")?);
                Ok(true)
            }
        }
    }
}

impl Component for LoginForm {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        LoginForm {
            link,
            on_logged_in: props.on_logged_in,
            error: None,
            form: Form::<FormModel>::new(FormModel::default()),
            task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.error = None;
        match self.handle_message(msg) {
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
        type Field = yew_form::Field<FormModel>;
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
                    oninput=self.link.callback(|_| Msg::Update) />
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
                <div class="form-group">
                  <button
                    type="submit"
                    class="btn btn-primary"
                    disabled=self.task.is_some()
                    onclick=self.link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})>
                    {"Login"}
                  </button>
                </div>
                <div class="form-group">
                { if let Some(e) = &self.error {
                    html! { e.to_string() }
                  } else { html! {} }
                }
                </div>
            </form>
        }
    }
}
