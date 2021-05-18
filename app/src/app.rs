use crate::cookies::get_cookie;
use crate::login::LoginForm;
use crate::logout::LogoutButton;
use crate::user_table::UserTable;
use yew::prelude::*;
use yew::services::ConsoleService;

pub struct App {
    link: ComponentLink<Self>,
    user_name: Option<String>,
}

pub enum Msg {
    Login(String),
    Logout,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        App {
            link: link.clone(),
            user_name: get_cookie("user_id").unwrap_or_else(|e| {
                ConsoleService::error(&e.to_string());
                None
            }),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Login(user_name) => {
                self.user_name = Some(user_name);
            }
            Msg::Logout => {
                self.user_name = None;
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
                    html! {
                      <div>
                        <LogoutButton on_logged_out=self.link.callback(|_| Msg::Logout) />
                        <UserTable />
                      </div>
                    }
                } else {
                    html! {<LoginForm on_logged_in=self.link.callback(|u| Msg::Login(u))/>}
                }}
            </div>
        }
    }
}
