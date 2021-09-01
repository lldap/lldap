use crate::api::HostService;
use anyhow::{anyhow, Result};
use graphql_client::GraphQLQuery;
use yew::format::Json;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_users.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::graphql"
)]
pub struct ListUsersQuery;

use list_users_query::{RequestFilter, ResponseData};

type User = list_users_query::ListUsersQueryUsers;

pub struct UserTable {
    link: ComponentLink<Self>,
    users: Option<Result<Vec<User>>>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    ListUsersResponse(Result<ResponseData>),
}

impl UserTable {
    fn get_users(&mut self, req: Option<RequestFilter>) {
        self._task = HostService::graphql_query::<ListUsersQuery>(
            list_users_query::Variables { filters: req },
            self.link.callback(Msg::ListUsersResponse),
            "Error trying to fetch users",
        )
        .map_err(|e| {
            ConsoleService::log(&e.to_string());
            e
        })
        .ok();
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
        table.get_users(None);
        table
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::ListUsersResponse(Ok(users)) => {
                self.users = Some(Ok(users.users.into_iter().collect()));
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
        let make_user_row = |user: &User| {
            html! {
                <tr>
                    <td>{&user.id}</td>
                    <td>{&user.email}</td>
                    <td>{&user.display_name}</td>
                    <td>{&user.first_name}</td>
                    <td>{&user.last_name}</td>
                    <td>{&user.creation_date.with_timezone(&chrono::Local)}</td>
                </tr>
            }
        };
        let make_table = |users: &Vec<User>| {
            html! {
                <table>
                  <tr>
                    <th>{"User ID"}</th>
                    <th>{"Email"}</th>
                    <th>{"Display name"}</th>
                    <th>{"First name"}</th>
                    <th>{"Last name"}</th>
                    <th>{"Creation date"}</th>
                  </tr>
                  {users.iter().map(make_user_row).collect::<Vec<_>>()}
                </table>
            }
        };
        match &self.users {
            None => html! {{"Loading..."}},
            Some(Err(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            Some(Ok(users)) => make_table(users),
        }
    }
}
