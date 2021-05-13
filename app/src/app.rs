use crate::login::LoginForm;
use crate::user_table::UserTable;
use anyhow::{anyhow, Result};
use wasm_bindgen::JsCast;
use yew::prelude::*;

pub struct App {
    link: ComponentLink<Self>,
    user_name: Option<String>,
}

pub enum Msg {
    Login(String),
}

fn extract_user_id_cookie() -> Result<String> {
    let document = web_sys::window()
        .unwrap()
        .document()
        .unwrap()
        .dyn_into::<web_sys::HtmlDocument>()
        .unwrap();
    let cookies = document.cookie().unwrap();
    yew::services::ConsoleService::info(&cookies);
    cookies
        .split(";")
        .filter_map(|c| c.split_once('='))
        .map(|(name, value)| {
            if name == "user_id" {
                Ok(value.into())
            } else {
                Err(anyhow!("Wrong cookie"))
            }
        })
        .filter(Result::is_ok)
        .next()
        .unwrap_or(Err(anyhow!("User ID cookie not found in response")))
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        App {
            link: link.clone(),
            user_name: extract_user_id_cookie().ok(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Login(user_name) => {
                self.user_name = Some(user_name);
            }
        }
        true
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <div>
                <h1>{ "LLDAP" }</h1>
                {if self.user_name.is_some() {
                    html! {<UserTable />}
                } else {
                    html! {<LoginForm on_logged_in=self.link.callback(|u| { Msg::Login(u) })/>}
                }}
            </div>
        }
    }
}
