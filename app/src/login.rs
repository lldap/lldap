use crate::api::HostService;
use anyhow::{anyhow, Context, Result};
use lldap_model::*;
use wasm_bindgen::JsCast;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};
use yew::FocusEvent;

pub struct LoginForm {
    link: ComponentLink<Self>,
    on_logged_in: Callback<(String, bool)>,
    error: Option<anyhow::Error>,
    node_ref: NodeRef,
    login_start: Option<opaque::client::login::ClientLogin>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_in: Callback<(String, bool)>,
}

pub enum Msg {
    Submit,
    AuthenticationStartResponse(Result<Box<login::ServerLoginStartResponse>>),
    AuthenticationFinishResponse(Result<(String, bool)>),
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

impl LoginForm {
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
                let username = get_form_field("username")
                    .ok_or_else(|| anyhow!("Could not get username from form"))?;
                let password = get_form_field("password")
                    .ok_or_else(|| anyhow!("Could not get password from form"))?;
                let mut rng = rand::rngs::OsRng;
                let login_start_request = opaque::client::login::start_login(&password, &mut rng)
                    .context("Could not initialize login")?;
                self.login_start = Some(login_start_request.state);
                let req = login::ClientLoginStartRequest {
                    username,
                    login_start_request: login_start_request.message,
                };
                self.call_backend(
                    HostService::login_start,
                    req,
                    Msg::AuthenticationStartResponse,
                )?;
                Ok(())
            }
            Msg::AuthenticationStartResponse(Ok(res)) => {
                debug_assert!(self.login_start.is_some());
                let login_finish = match opaque::client::login::finish_login(
                    self.login_start.as_ref().unwrap().clone(),
                    res.credential_response,
                ) {
                    Err(e) => {
                        // Common error, we want to print a full error to the console but only a
                        // simple one to the user.
                        ConsoleService::error(&format!("Invalid username or password: {}", e));
                        self.error = Some(anyhow!("Invalid username or password"));
                        return Ok(());
                    }
                    Ok(l) => l,
                };
                let req = login::ClientLoginFinishRequest {
                    server_data: res.server_data,
                    credential_finalization: login_finish.message,
                };
                self.call_backend(
                    HostService::login_finish,
                    req,
                    Msg::AuthenticationFinishResponse,
                )?;
                Ok(())
            }
            Msg::AuthenticationStartResponse(Err(e)) => Err(anyhow!(
                "Could not log in (invalid response to login start): {}",
                e
            )),
            Msg::AuthenticationFinishResponse(Ok(user_info)) => {
                self.on_logged_in.emit(user_info);
                Ok(())
            }
            Msg::AuthenticationFinishResponse(Err(e)) => Err(anyhow!("Could not log in: {}", e)),
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
            node_ref: NodeRef::default(),
            login_start: None,
            _task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
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
                    <label for="username">{"User name:"}</label>
                    <input type="text" id="username" />
                </div>
                <div>
                    <label for="password">{"Password:"}</label>
                    <input type="password" id="password" />
                </div>
                <button type="submit">{"Login"}</button>
                <div>
                { if let Some(e) = &self.error {
                    html! { e.to_string() }
                  } else { html! {} }
                }
                </div>
            </form>
        }
    }
}
