use crate::api::HostService;
use anyhow::Error;
use lldap_model::*;
use yew::format::Json;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

pub struct App {
    link: ComponentLink<Self>,
    ipservice: HostService,
    task: Option<FetchTask>,
    users: Option<Vec<User>>,
}

pub enum Msg {
    //BindRequest(BindRequest),
    ListUsersRequest(ListUsersRequest),
    ListUsersResponse(Result<Vec<User>, Error>),
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        App {
            link: link.clone(),
            ipservice: HostService::default(),
            task: None,
            users: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::ListUsersRequest(req) => {
                match self
                    .ipservice
                    .list_users(req, self.link.callback(Msg::ListUsersResponse))
                {
                    Ok(task) => self.task = Some(task),
                    Err(e) => {
                        self.task = None;
                        ConsoleService::log(
                            format!("Error trying to fetch users: {:?}", e).as_str(),
                        )
                    }
                }
            }
            Msg::ListUsersResponse(Ok(users)) => {
                self.users = Some(users);
                ConsoleService::log(format!("Response: {:?}", Json(&self.users)).as_str());
            }
            Msg::ListUsersResponse(Err(e)) => {
                self.task = None;
                ConsoleService::log(format!("Error listing users: {:?}", e).as_str())
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
                <button onclick=self.link.callback(|_| Msg::ListUsersRequest(ListUsersRequest{filters: None}))>{ "Fetch users" }</button>
                <p>{ format!("Users: {:?}", &self.users) }</p>
            </div>
        }
    }
}
