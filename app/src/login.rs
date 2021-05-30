use crate::api::HostService;
use anyhow::{anyhow, Result};
use lldap_model::*;
use wasm_bindgen::JsCast;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};
use yew::FocusEvent;

pub struct LoginForm {
    link: ComponentLink<Self>,
    on_logged_in: Callback<String>,
    error: Option<anyhow::Error>,
    node_ref: NodeRef,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_in: Callback<String>,
}

pub enum Msg {
    Submit,
    AuthenticationResponse(Result<String>),
}

impl LoginForm {
    fn set_error(&mut self, error: anyhow::Error) {
        ConsoleService::error(&error.to_string());
        self.error = Some(error);
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
            _task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Submit => {
                let document = web_sys::window().unwrap().document().unwrap();
                let username = document
                    .get_element_by_id("username")
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value();
                let password = document
                    .get_element_by_id("password")
                    .unwrap()
                    .dyn_into::<web_sys::HtmlInputElement>()
                    .unwrap()
                    .value();
                let req = BindRequest {
                    name: username,
                    password,
                };
                match HostService::authenticate(
                    req,
                    self.link.callback(Msg::AuthenticationResponse),
                ) {
                    Ok(task) => self._task = Some(task),
                    Err(e) => self.set_error(e),
                }
            }
            Msg::AuthenticationResponse(Ok(user_id)) => {
                self.on_logged_in.emit(user_id);
            }
            Msg::AuthenticationResponse(Err(e)) => {
                self.set_error(anyhow!("Could not log in: {}", e));
            }
        };
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
