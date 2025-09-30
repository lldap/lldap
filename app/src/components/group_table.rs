use crate::{
    DateToLocalDisplay,
    components::{
        delete_group::DeleteGroup,
        router::{AppRoute, Link},
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_list.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupList;

use get_group_list::ResponseData;

pub type Group = get_group_list::GetGroupListGroups;

pub struct GroupTable {
    common: CommonComponentParts<Self>,
    groups: Option<Vec<Group>>,
}

pub enum Msg {
    ListGroupsResponse(Result<ResponseData>),
    OnGroupDeleted(i64),
    OnError(Error),
}

impl CommonComponent<GroupTable> for GroupTable {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
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

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for GroupTable {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = GroupTable {
            common: CommonComponentParts::<Self>::create(),
            groups: None,
        };
        table.common.call_graphql::<GetGroupList, _>(
            ctx,
            get_group_list::Variables {},
            Msg::ListGroupsResponse,
            "Error trying to fetch groups",
        );
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div>
              {self.view_groups(ctx)}
              {self.view_errors()}
            </div>
        }
    }
}

impl GroupTable {
    fn view_groups(&self, ctx: &Context<Self>) -> Html {
        let make_table = |groups: &Vec<Group>| {
            html! {
                <div class="table-responsive">
                  <table class="table table-hover">
                    <thead>
                      <tr>
                        <th>{"Group name"}</th>
                        <th>{"Creation date"}</th>
                        <th>{"Delete"}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {groups.iter().map(|u| self.view_group(ctx, u)).collect::<Vec<_>>()}
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

    fn view_group(&self, ctx: &Context<Self>, group: &Group) -> Html {
        let link = ctx.link();
        html! {
          <tr key={group.id}>
              <td>
                <Link to={AppRoute::GroupDetails{group_id: group.id}}>
                  {&group.display_name}
                </Link>
              </td>
              <td>
                {&group.creation_date.to_local_date_display()}
              </td>
              <td>
                <DeleteGroup
                  group={group.clone()}
                  on_group_deleted={link.callback(Msg::OnGroupDeleted)}
                  on_error={link.callback(Msg::OnError)}/>
              </td>
          </tr>
        }
    }

    fn view_errors(&self) -> Html {
        match &self.common.error {
            None => html! {},
            Some(e) => html! {<div>{"Error: "}{e.to_string()}</div>},
        }
    }
}
