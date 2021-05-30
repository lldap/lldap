use crate::api::HostService;
use anyhow::{anyhow, Result};
use lldap_model::*;
use yew::format::Json;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

pub struct UserTable {
    link: ComponentLink<Self>,
    users: Option<Result<Vec<User>>>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    ListUsersResponse(Result<Vec<User>>),
}

impl UserTable {
    fn get_users(&mut self, req: ListUsersRequest) {
        match HostService::list_users(req, self.link.callback(Msg::ListUsersResponse)) {
            Ok(task) => self._task = Some(task),
            Err(e) => {
                self._task = None;
                ConsoleService::log(format!("Error trying to fetch users: {}", e).as_str())
            }
        };
    }
}

impl Component for UserTable {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut table = UserTable {
            link,
            _task: None,
            users: None,
        };
        table.get_users(ListUsersRequest { filters: None });
        table
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::ListUsersResponse(Ok(users)) => {
                self.users = Some(Ok(users));
                ConsoleService::log(format!("Response: {:?}", Json(&self.users)).as_str());
                true
            }
            Msg::ListUsersResponse(Err(e)) => {
                self.users = Some(Err(anyhow!("Error listing users: {}", e)));
                true
            }
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <p>{
                match &self.users {
                     None => "Loading...".to_string(),
                     Some(Ok(users)) => format!("Users: {:?}", &users),
                     Some(Err(e)) => e.to_string(),
                }
            }</p>
        }
    }
}
