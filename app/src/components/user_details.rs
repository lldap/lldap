use crate::{
    components::{
        add_user_to_group::AddUserToGroupComponent,
        remove_user_from_group::RemoveUserFromGroupComponent,
        router::{AppRoute, NavButton},
        user_details_form::UserDetailsForm,
    },
    infra::api::HostService,
};
use anyhow::{bail, Error, Result};
use graphql_client::GraphQLQuery;
use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};

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
    link: ComponentLink<Self>,
    props: Props,
    /// The user info. If none, the error is in `error`. If `error` is None, then we haven't
    /// received the server response yet.
    user: Option<User>,
    /// Error message displayed to the user.
    error: Option<Error>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the user details response, either the user data or an error.
    UserDetailsResponse(Result<get_user_details::ResponseData>),
    OnError(Error),
    OnUserAddedToGroup(Group),
    OnUserRemovedFromGroup(Group),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
}

impl UserDetails {
    fn get_user_details(&mut self) {
        self._task = HostService::graphql_query::<GetUserDetails>(
            get_user_details::Variables {
                id: self.props.username.clone(),
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
            Msg::OnUserRemovedFromGroup(group) => {
                self.user.as_mut().unwrap().groups.retain(|g| g != &group);
            }
        }
        Ok(true)
    }

    fn view_messages(&self, error: &Option<Error>) -> Html {
        if let Some(e) = error {
            html! {
              <div>
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
                <RemoveUserFromGroupComponent
                  username=u.id.clone()
                  group=group.clone()
                  is_admin=self.props.is_admin
                  on_user_removed_from_group=self.link.callback(Msg::OnUserRemovedFromGroup)
                  on_error=self.link.callback(Msg::OnError)/>
              </tr>
            }
        };
        html! {
        <div>
          <h3>{"Group memberships"}</h3>
          <div class="table-responsive">
            <table class="table table-striped">
              <thead>
                <tr key="headerRow">
                  <th>{"Group"}</th>
                  { if self.props.is_admin { html!{ <th></th> }} else { html!{} }}
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
                <hr/>
                <tr key="groupToAddRow">
                  {self.view_add_group_button(u)}
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        }
    }

    fn view_add_group_button(&self, u: &User) -> Html {
        if self.props.is_admin {
            html! {
                <AddUserToGroupComponent
                    username=u.id.clone()
                    groups=u.groups.clone()
                    on_error=self.link.callback(Msg::OnError)
                    on_user_added_to_group=self.link.callback(Msg::OnUserAddedToGroup)/>
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
            link,
            props,
            _task: None,
            user: None,
            error: None,
        };
        table.get_user_details();
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
        match (&self.user, &self.error) {
            (None, None) => html! {{"Loading..."}},
            (None, Some(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            (Some(u), error) => {
                html! {
                    <div>
                      <UserDetailsForm
                        user=u.clone()
                        on_error=self.link.callback(Msg::OnError)/>
                      {self.view_messages(error)}
                      {self.view_group_memberships(u)}
                      <div>
                        <NavButton
                          route=AppRoute::ChangePassword(u.id.clone())
                          classes="btn btn-primary">
                            {"Change password"}
                        </NavButton>
                      </div>
                    </div>
                }
            }
        }
    }
}
