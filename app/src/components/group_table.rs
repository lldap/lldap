use crate::{
    //components::{
    //    delete_group::DeleteGroup,
    //    router::{AppRoute, Link},
    //},
    infra::api::HostService,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_list.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupList;

use get_group_list::ResponseData;

type Group = get_group_list::GetGroupListGroups;

pub struct GroupTable {
    link: ComponentLink<Self>,
    groups: Option<Vec<Group>>,
    error: Option<Error>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    ListGroupsResponse(Result<ResponseData>),
    OnGroupDeleted(i64),
    OnError(Error),
}

impl GroupTable {
    fn get_groups(&mut self) {
        self._task = HostService::graphql_query::<GetGroupList>(
            get_group_list::Variables {},
            self.link.callback(Msg::ListGroupsResponse),
            "Error trying to fetch groups",
        )
        .map_err(|e| {
            ConsoleService::log(&e.to_string());
            e
        })
        .ok();
    }
}

impl Component for GroupTable {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut table = GroupTable {
            link,
            _task: None,
            groups: None,
            error: None,
        };
        table.get_groups();
        table
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.error = None;
        match self.handle_msg(msg) {
            Err(e) => {
                ConsoleService::error(&e.to_string());
                self.error = Some(e);
                true
            }
            Ok(b) => b,
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <div>
              {self.view_groups()}
              {self.view_errors()}
            </div>
        }
    }
}

impl GroupTable {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ListGroupsResponse(groups) => {
                self.groups = Some(groups?.groups.into_iter().collect());
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::OnGroupDeleted(group_id) => {
                debug_assert!(self.groups.is_some());
                self.groups.as_mut().unwrap().retain(|u| u.id != group_id);
                Ok(true)
            }
        }
    }

    fn view_groups(&self) -> Html {
        let make_table = |groups: &Vec<Group>| {
            html! {
                <div class="table-responsive">
                  <table class="table table-striped">
                    <thead>
                      <tr>
                        <th>{"Group ID"}</th>
                        <th>{"Display name"}</th>
                        //<th>{"Delete"}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {groups.iter().map(|u| self.view_group(u)).collect::<Vec<_>>()}
                    </tbody>
                  </table>
                </div>
            }
        };
        match &self.groups {
            None => html! {{"Loading..."}},
            Some(groups) => make_table(groups),
        }
    }

    fn view_group(&self, group: &Group) -> Html {
        html! {
          <tr key=group.id.clone()>
              //<td><Link route=AppRoute::GroupDetails(group.id.clone())>{&group.id}</Link></td>
              <td>{&group.id}</td>
              <td>{&group.display_name}</td>
              //<td>
              //  <DeleteGroup
              //    groupname=group.id.clone()
              //    on_group_deleted=self.link.callback(Msg::OnGroupDeleted)
              //    on_error=self.link.callback(Msg::OnError)/>
              //</td>
          </tr>
        }
    }

    fn view_errors(&self) -> Html {
        match &self.error {
            None => html! {},
            Some(e) => html! {<div>{"Error: "}{e.to_string()}</div>},
        }
    }
}
