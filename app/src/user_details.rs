use crate::api::HostService;
use anyhow::{anyhow, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_details.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::graphql"
)]
pub struct GetUserDetails;

type User = get_user_details::GetUserDetailsUser;

pub struct UserDetails {
    link: ComponentLink<Self>,
    username: String,
    user: Option<Result<User>>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    UserDetailsResponse(Result<get_user_details::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub username: String,
}

impl UserDetails {
    fn get_user_details(&mut self) {
        self._task = HostService::graphql_query::<GetUserDetails>(
            get_user_details::Variables {
                id: self.username.clone(),
            },
            self.link.callback(Msg::UserDetailsResponse),
            "Error trying to fetch user details",
        )
        .map_err(|e| {
            ConsoleService::log(&e.to_string());
            e
        })
        .ok();
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
                self.user = Some(Ok(user.user));
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
                        <div>{"User ID: "} {&u.id}</div>
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
