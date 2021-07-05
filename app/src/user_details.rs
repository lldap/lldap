use crate::api::HostService;
use anyhow::{anyhow, Result};
use lldap_model::*;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

pub struct UserDetails {
    link: ComponentLink<Self>,
    username: String,
    user: Option<Result<User>>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    UserDetailsResponse(Result<User>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub username: String,
}

impl UserDetails {
    fn get_user_details(&mut self) {
        match HostService::get_user_details(
            &self.username,
            self.link.callback(Msg::UserDetailsResponse),
        ) {
            Ok(task) => self._task = Some(task),
            Err(e) => {
                self._task = None;
                ConsoleService::log(format!("Error trying to fetch user details: {}", e).as_str())
            }
        };
    }
}

impl Component for UserDetails {
    type Message = Msg;
    // The username.
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut table = UserDetails {
            link,
            username: props.username,
            _task: None,
            user: None,
        };
        table.get_user_details();
        table
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::UserDetailsResponse(Ok(user)) => {
                self.user = Some(Ok(user));
                true
            }
            Msg::UserDetailsResponse(Err(e)) => {
                self.user = Some(Err(anyhow!("Error getting user details: {}", e)));
                true
            }
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        match &self.user {
            None => html! {{"Loading..."}},
            Some(Err(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            Some(Ok(u)) => {
                html! {
                    <div>
                        <div>{"User ID: "} {&u.user_id}</div>
                        <div>{"Email: "}{&u.email}</div>
                        <div>{"Display name: "}{&u.display_name.as_ref().unwrap_or(&String::new())}</div>
                        <div>{"First name: "}{&u.first_name.as_ref().unwrap_or(&String::new())}</div>
                        <div>{"Last name: "}{&u.last_name.as_ref().unwrap_or(&String::new())}</div>
                        <div>{"Creation date: "}{&u.creation_date}</div>
                    </div>
                }
            }
        }
    }
}
