use crate::{
    components::{
        add_user_to_group::AddUserToGroupComponent,
        remove_user_from_group::RemoveUserFromGroupComponent,
        router::{AppRoute, Link, NavButton},
        user_details_form::UserDetailsForm,
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_details.graphql",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserDetails;

pub type User = get_user_details::GetUserDetailsUser;
pub type Group = get_user_details::GetUserDetailsUserGroups;

pub struct UserDetails {
    common: CommonComponentParts<Self>,
    /// The user info. If none, the error is in `error`. If `error` is None, then we haven't
    /// received the server response yet.
    user: Option<User>,
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the user details response, either the user data or an error.
    UserDetailsResponse(Result<get_user_details::ResponseData>),
    OnError(Error),
    OnUserAddedToGroup(Group),
    OnUserRemovedFromGroup((String, i64)),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
}

impl CommonComponent<UserDetails> for UserDetails {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::UserDetailsResponse(response) => match response {
                Ok(user) => self.user = Some(user.user),
                Err(e) => {
                    self.user = None;
                    bail!("Error getting user details: {}", e);
                }
            },
            Msg::OnError(e) => return Err(e),
            Msg::OnUserAddedToGroup(group) => {
                self.user.as_mut().unwrap().groups.push(group);
            }
            Msg::OnUserRemovedFromGroup((_, group_id)) => {
                self.user
                    .as_mut()
                    .unwrap()
                    .groups
                    .retain(|g| g.id != group_id);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl UserDetails {
    fn get_user_details(&mut self) {
        self.common.call_graphql::<GetUserDetails, _>(
            get_user_details::Variables {
                id: self.common.username.clone(),
            },
            Msg::UserDetailsResponse,
            "Error trying to fetch user details",
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

    fn view_group_memberships(&self, u: &User) -> Html {
        let make_group_row = |group: &Group| {
            let display_name = group.display_name.clone();
            html! {
              <tr key="groupRow_".to_string() + &display_name>
                {if self.common.is_admin { html! {
                  <>
                    <td>
                      <Link route=AppRoute::GroupDetails(group.id)>
                        {&group.display_name}
                      </Link>
                    </td>
                    <td>
                      <RemoveUserFromGroupComponent
                        username=u.id.clone()
                        group_id=group.id
                        on_user_removed_from_group=self.common.callback(Msg::OnUserRemovedFromGroup)
                        on_error=self.common.callback(Msg::OnError)/>
                    </td>
                  </>
                } } else { html! {
                  <td>{&group.display_name}</td>
                } } }
              </tr>
            }
        };
        html! {
          <>
            <h5 class="row m-3 fw-bold">{"Group memberships"}</h5>
            <div class="table-responsive">
              <table class="table table-striped">
                <thead>
                  <tr key="headerRow">
                    <th>{"Group"}</th>
                    { if self.common.is_admin { html!{ <th></th> }} else { html!{} }}
                  </tr>
                </thead>
                <tbody>
                  {if u.groups.is_empty() {
                    html! {
                      <tr key="EmptyRow">
                        <td>{"Not member of any group"}</td>
                      </tr>
                    }
                  } else {
                    html! {<>{u.groups.iter().map(make_group_row).collect::<Vec<_>>()}</>}
                  }}
                </tbody>
              </table>
            </div>
          </>
        }
    }

    fn view_add_group_button(&self, u: &User) -> Html {
        if self.common.is_admin {
            html! {
                <AddUserToGroupComponent
                    username=u.id.clone()
                    groups=u.groups.clone()
                    on_error=self.common.callback(Msg::OnError)
                    on_user_added_to_group=self.common.callback(Msg::OnUserAddedToGroup)/>
            }
        } else {
            html! {}
        }
    }
}

impl Component for UserDetails {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut table = Self {
            common: CommonComponentParts::<Self>::create(props, link),
            user: None,
        };
        table.get_user_details();
        table
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        match (&self.user, &self.common.error) {
            (None, None) => html! {{"Loading..."}},
            (None, Some(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            (Some(u), error) => {
                html! {
                  <>
                    <h3>{u.id.to_string()}</h3>
                    <UserDetailsForm
                      user=u.clone() />
                    <div class="row justify-content-center">
                      <NavButton
                        route=AppRoute::ChangePassword(u.id.clone())
                        classes="btn btn-primary col-auto">
                          {"Change password"}
                      </NavButton>
                    </div>
                    {self.view_group_memberships(u)}
                    {self.view_add_group_button(u)}
                    {self.view_messages(error)}
                  </>
                }
            }
        }
    }
}
