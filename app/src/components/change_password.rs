use crate::{
    components::router::{AppRoute, NavButton},
    infra::api::HostService,
};
use anyhow::{anyhow, bail, Context, Result};
use lldap_auth::*;
use wasm_bindgen::JsCast;
use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
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

pub struct ChangePasswordForm {
    link: ComponentLink<Self>,
    username: String,
    error: Option<anyhow::Error>,
    node_ref: NodeRef,
    opaque_data: OpaqueData,
    successfully_changed_password: bool,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub username: String,
}

pub enum Msg {
    Submit,
    AuthenticationStartResponse(Result<Box<login::ServerLoginStartResponse>>),
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
}

fn get_form_field(field_id: &str) -> Option<String> {
    let document = web_sys::window()?.document()?;
    Some(
        document
            .get_element_by_id(field_id)?
            .dyn_into::<web_sys::HtmlInputElement>()
            .ok()?
            .value(),
    )
}

fn clear_form_fields() -> Option<()> {
    let document = web_sys::window()?.document()?;

    let clear_field = |id| {
        document
            .get_element_by_id(id)?
            .dyn_into::<web_sys::HtmlInputElement>()
            .ok()?
            .set_value("");
        Some(())
    };
    clear_field("oldPassword");
    clear_field("newPassword");
    clear_field("confirmPassword");
    None
}

impl ChangePasswordForm {
    fn set_error(&mut self, error: anyhow::Error) {
        ConsoleService::error(&error.to_string());
        self.error = Some(error);
    }

    fn call_backend<M, Req, C, Resp>(&mut self, method: M, req: Req, callback: C) -> Result<()>
    where
        M: Fn(Req, Callback<Resp>) -> Result<FetchTask>,
        C: Fn(Resp) -> <Self as Component>::Message + 'static,
    {
        self._task = Some(method(req, self.link.callback(callback))?);
        Ok(())
    }

    fn handle_message(&mut self, msg: <Self as Component>::Message) -> Result<()> {
        match msg {
            Msg::Submit => {
                let old_password = get_form_field("oldPassword")
                    .ok_or_else(|| anyhow!("Could not get old password from form"))?;
                let new_password = get_form_field("newPassword")
                    .ok_or_else(|| anyhow!("Could not get new password from form"))?;
                let confirm_password = get_form_field("confirmPassword")
                    .ok_or_else(|| anyhow!("Could not get confirmation password from form"))?;
                if new_password != confirm_password {
                    bail!("Confirmation password doesn't match");
                }
                let mut rng = rand::rngs::OsRng;
                let login_start_request =
                    opaque::client::login::start_login(&old_password, &mut rng)
                        .context("Could not initialize login")?;
                self.opaque_data = OpaqueData::Login(login_start_request.state);
                let req = login::ClientLoginStartRequest {
                    username: self.username.clone(),
                    login_start_request: login_start_request.message,
                };
                self.call_backend(
                    HostService::login_start,
                    req,
                    Msg::AuthenticationStartResponse,
                )?;
                Ok(())
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
                let mut rng = rand::rngs::OsRng;
                let new_password = get_form_field("newPassword")
                    .ok_or_else(|| anyhow!("Could not get new password from form"))?;
                let registration_start_request =
                    opaque::client::registration::start_registration(&new_password, &mut rng)
                        .context("Could not initiate password change")?;
                let req = registration::ClientRegistrationStartRequest {
                    username: self.username.clone(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = OpaqueData::Registration(registration_start_request.state);
                self.call_backend(
                    HostService::register_start,
                    req,
                    Msg::RegistrationStartResponse,
                )?;
                Ok(())
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
                        self.call_backend(
                            HostService::register_finish,
                            req,
                            Msg::RegistrationFinishResponse,
                        )
                    }
                    _ => panic!("Unexpected data in opaque_data field"),
                }
            }
            Msg::RegistrationFinishResponse(response) => {
                if response.is_ok() {
                    self.successfully_changed_password = true;
                    clear_form_fields();
                }
                response
            }
        }
    }
}

impl Component for ChangePasswordForm {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        ChangePasswordForm {
            link,
            username: props.username,
            error: None,
            node_ref: NodeRef::default(),
            opaque_data: OpaqueData::None,
            successfully_changed_password: false,
            _task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.successfully_changed_password = false;
        self.error = None;
        if let Err(e) = self.handle_message(msg) {
            self.set_error(e);
        }
        true
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <form ref=self.node_ref.clone() onsubmit=self.link.callback(|e: FocusEvent| { e.prevent_default(); Msg::Submit })>
                <div>
                    <label for="oldPassword">{"Old password:"}</label>
                    <input type="password" id="oldPassword" autocomplete="current-password" required=true />
                </div>
                <div>
                    <label for="newPassword">{"New password:"}</label>
                    <input type="password" id="newPassword" autocomplete="new-password" required=true minlength="8" />
                </div>
                <div>
                    <label for="confirmPassword">{"Confirm new password:"}</label>
                    <input type="password" id="confirmPassword" autocomplete="new-password" required=true minlength="8" />
                </div>
                <button type="submit">{"Submit"}</button>
                <div>
                { if let Some(e) = &self.error {
                    html! { e.to_string() }
                  } else if self.successfully_changed_password {
                    html! {
                      <div>
                        <span>{"Successfully changed the password"}</span>
                      </div>
                    }
                  } else { html! {} }
                }
                </div>
                <div>
                  <NavButton route=AppRoute::UserDetails(self.username.clone())>{"Back"}</NavButton>
                </div>
            </form>
        }
    }
}
