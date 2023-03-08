use crate::{
    components::{
        add_group_member::{self, AddGroupMemberComponent},
        remove_user_from_group::RemoveUserFromGroupComponent,
        router::{AppRoute, Link},
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_details.graphql",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupDetails;

pub type Group = get_group_details::GetGroupDetailsGroup;
pub type User = get_group_details::GetGroupDetailsGroupUsers;
pub type AddGroupMemberUser = add_group_member::User;

pub struct GroupDetails {
    common: CommonComponentParts<Self>,
    /// The group info. If none, the error is in `error`. If `error` is None, then we haven't
    /// received the server response yet.
    group: Option<Group>,
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the group details response, either the group data or an error.
    GroupDetailsResponse(Result<get_group_details::ResponseData>),
    OnError(Error),
    OnUserAddedToGroup(AddGroupMemberUser),
    OnUserRemovedFromGroup((String, i64)),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub group_id: i64,
}

impl GroupDetails {
    fn get_group_details(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetGroupDetails, _>(
            ctx,
            get_group_details::Variables {
                id: ctx.props().group_id,
            },
            Msg::GroupDetailsResponse,
            "Error trying to fetch group details",
        );
    }

    fn view_messages(&self, error: &Option<Error>) -> Html {
        if let Some(e) = error {
            html! {
              <div class="alert alert-danger">
                <span>{"Error: "}{e.to_string()}</span>
              </div>
            }
        } else {
            html! {}
        }
    }

    fn view_details(&self, g: &Group) -> Html {
        html! {
          <>
            <h3>{g.display_name.to_string()}</h3>
            <div class="py-3">
              <form class="form">
                <div class="form-group row mb-3">
                  <label for="displayName"
                    class="form-label col-4 col-form-label">
                    {"Group: "}
                  </label>
                  <div class="col-8">
                    <span id="groupId" class="form-constrol-static">{g.display_name.to_string()}</span>
                  </div>
                </div>
                <div class="form-group row mb-3">
                  <label for="creationDate"
                    class="form-label col-4 col-form-label">
                    {"Creation date: "}
                  </label>
                  <div class="col-8">
                    <span id="creationDate" class="form-constrol-static">{g.creation_date.naive_local().date()}</span>
                  </div>
                </div>
                <div class="form-group row mb-3">
                  <label for="uuid"
                    class="form-label col-4 col-form-label">
                    {"UUID: "}
                  </label>
                  <div class="col-8">
                    <span id="uuid" class="form-constrol-static">{g.uuid.to_string()}</span>
                  </div>
                </div>
              </form>
            </div>
          </>
        }
    }

    fn view_user_list(&self, ctx: &Context<Self>, g: &Group) -> Html {
        let link = ctx.link();
        let make_user_row = |user: &User| {
            let user_id = user.id.clone();
            let display_name = user.display_name.clone();
            html! {
              <tr>
                <td>
                  <Link to={AppRoute::UserDetails{user_id: user_id.clone()}}>
                    {user_id.clone()}
                  </Link>
                </td>
                <td>{display_name}</td>
                <td>
                  <RemoveUserFromGroupComponent
                    username={user_id}
                    group_id={g.id}
                    on_user_removed_from_group={link.callback(Msg::OnUserRemovedFromGroup)}
                    on_error={link.callback(Msg::OnError)}/>
                </td>
              </tr>
            }
        };
        html! {
          <>
            <h5 class="fw-bold">{"Members"}</h5>
            <div class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr key="headerRow">
                    <th>{"User Id"}</th>
                    <th>{"Display name"}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {if g.users.is_empty() {
                    html! {
                      <tr key="EmptyRow">
                        <td>{"There are no users in this group."}</td>
                        <td/>
                      </tr>
                    }
                  } else {
                    html! {<>{g.users.iter().map(make_user_row).collect::<Vec<_>>()}</>}
                  }}
                </tbody>
              </table>
            </div>
          </>
        }
    }

    fn view_add_user_button(&self, ctx: &Context<Self>, g: &Group) -> Html {
        let link = ctx.link();
        let users: Vec<_> = g
            .users
            .iter()
            .map(|u| AddGroupMemberUser {
                id: u.id.clone(),
                display_name: u.display_name.clone(),
            })
            .collect();
        html! {
            <AddGroupMemberComponent
                group_id={g.id}
                users={users}
                on_error={link.callback(Msg::OnError)}
                on_user_added_to_group={link.callback(Msg::OnUserAddedToGroup)}/>
        }
    }
}

impl CommonComponent<GroupDetails> for GroupDetails {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::GroupDetailsResponse(response) => match response {
                Ok(group) => self.group = Some(group.group),
                Err(e) => {
                    self.group = None;
                    bail!("Error getting user details: {}", e);
                }
            },
            Msg::OnError(e) => return Err(e),
            Msg::OnUserAddedToGroup(user) => {
                self.group.as_mut().unwrap().users.push(User {
                    id: user.id,
                    display_name: user.display_name,
                });
            }
            Msg::OnUserRemovedFromGroup((user_id, _)) => {
                self.group
                    .as_mut()
                    .unwrap()
                    .users
                    .retain(|u| u.id != user_id);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for GroupDetails {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = Self {
            common: CommonComponentParts::<Self>::create(),
            group: None,
        };
        table.get_group_details(ctx);
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match (&self.group, &self.common.error) {
            (None, None) => html! {{"Loading..."}},
            (None, Some(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            (Some(u), error) => {
                html! {
                    <div>
                      {self.view_details(u)}
                      {self.view_user_list(ctx, u)}
                      {self.view_add_user_button(ctx, u)}
                      {self.view_messages(error)}
                    </div>
                }
            }
        }
    }
}
