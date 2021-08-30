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

pub struct UserTable {
    link: ComponentLink<Self>,
    users: Option<Result<Vec<list_users_query::ListUsersQueryUsers>>>,
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
        match &self.users {
            None => html! {{"Loading..."}},
            Some(Err(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            Some(Ok(users)) => {
                let table_content: Vec<_> = users
                    .iter()
                    .map(|u| {
                        html! {
                            <tr>
                                <td>{&u.id}</td>
                                <td>{&u.email}</td>
                                <td>{&u.display_name.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.first_name.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.last_name.as_ref().unwrap_or(&String::new())}</td>
                                <td>{&u.creation_date.with_timezone(&chrono::Local)}</td>
                            </tr>
                        }
                    })
                    .collect();
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
                      {table_content}
                    </table>
                }
            }
        }
    }
}
