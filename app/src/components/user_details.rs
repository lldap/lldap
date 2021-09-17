use crate::{
    components::{
        add_user_to_group::AddUserToGroupComponent,
        router::{AppRoute, NavButton},
    },
    infra::api::HostService,
};
use anyhow::{anyhow, bail, Error, Result};
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

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/update_user.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdateUser;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/remove_user_from_group.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct RemoveUserFromGroup;

pub struct UserDetails {
    link: ComponentLink<Self>,
    /// Which user this is about.
    username: String,
    /// The user info. If none, the error is in `error`. If `error` is None, then we haven't
    /// received the server response yet.
    user: Option<User>,
    // Needed for the form.
    node_ref: NodeRef,
    /// Error message displayed to the user.
    error: Option<Error>,
    /// The request, while we're waiting for the server to reply.
    update_request: Option<update_user::UpdateUserInput>,
    /// True iff we just finished updating the user, to display a successful message.
    update_successful: bool,
    is_admin: bool,
    /// The group that we're requesting to remove, if any.
    group_to_remove: Option<Group>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the user details response, either the user data or an error.
    UserDetailsResponse(Result<get_user_details::ResponseData>),
    /// The user changed some fields and submitted the form for update.
    SubmitUserUpdateForm,
    /// Response after updating the user's details.
    UpdateFinished(Result<update_user::ResponseData>),
    SubmitRemoveGroup(Group),
    RemoveGroupResponse(Result<remove_user_from_group::ResponseData>),
    OnError(Error),
    OnUserAddedToGroup(Group),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
}

#[allow(clippy::ptr_arg)]
fn not_empty(s: &String) -> bool {
    !s.is_empty()
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

    fn submit_user_update_form(&mut self) -> Result<bool> {
        let base_user = self.user.as_ref().unwrap();
        let mut user_input = update_user::UpdateUserInput {
            id: self.username.clone(),
            email: None,
            displayName: None,
            firstName: None,
            lastName: None,
        };
        let mut should_send_form = false;
        let email = get_element("email")
            .filter(not_empty)
            .ok_or_else(|| anyhow!("Missing email"))?;
        if base_user.email != email {
            should_send_form = true;
            user_input.email = Some(email);
        }
        if base_user.display_name != get_element_or_empty("display_name") {
            should_send_form = true;
            user_input.displayName = Some(get_element_or_empty("display_name"));
        }
        if base_user.first_name != get_element_or_empty("first_name") {
            should_send_form = true;
            user_input.firstName = Some(get_element_or_empty("first_name"));
        }
        if base_user.last_name != get_element_or_empty("last_name") {
            should_send_form = true;
            user_input.lastName = Some(get_element_or_empty("last_name"));
        }
        if !should_send_form {
            return Ok(false);
        }
        self.update_request = Some(user_input.clone());
        let req = update_user::Variables { user: user_input };
        self._task = Some(HostService::graphql_query::<UpdateUser>(
            req,
            self.link.callback(Msg::UpdateFinished),
            "Error trying to update user",
        )?);
        Ok(false)
    }

    fn user_update_finished(&mut self, r: Result<update_user::ResponseData>) -> Result<bool> {
        match r {
            Err(e) => return Err(e),
            Ok(_) => {
                ConsoleService::log("Successfully updated user");
                self.update_successful = true;
                let User {
                    id,
                    display_name,
                    first_name,
                    last_name,
                    email,
                    creation_date,
                    groups,
                } = self.user.take().unwrap();
                let new_user = self.update_request.take().unwrap();
                self.user = Some(User {
                    id,
                    email: new_user.email.unwrap_or(email),
                    display_name: new_user.displayName.unwrap_or(display_name),
                    first_name: new_user.firstName.unwrap_or(first_name),
                    last_name: new_user.lastName.unwrap_or(last_name),
                    creation_date,
                    groups,
                });
            }
        };
        Ok(true)
    }

    fn submit_remove_group(&mut self, group: Group) -> Result<bool> {
        self._task = HostService::graphql_query::<RemoveUserFromGroup>(
            remove_user_from_group::Variables {
                user: self.username.clone(),
                group: group.id,
            },
            self.link.callback(Msg::RemoveGroupResponse),
            "Error trying to initiate removing the user from a group",
        )
        .map_err(|e| {
            ConsoleService::log(&e.to_string());
            e
        })
        .ok();
        self.group_to_remove = Some(group);
        Ok(true)
    }

    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        self.update_successful = false;
        match msg {
            Msg::UserDetailsResponse(response) => match response {
                Ok(user) => self.user = Some(user.user),
                Err(e) => {
                    self.user = None;
                    bail!("Error getting user details: {}", e);
                }
            },
            Msg::SubmitUserUpdateForm => return self.submit_user_update_form(),
            Msg::UpdateFinished(r) => return self.user_update_finished(r),
            Msg::SubmitRemoveGroup(group) => return self.submit_remove_group(group),
            Msg::RemoveGroupResponse(response) => {
                response?;
                let group = self.group_to_remove.take().unwrap();
                // Remove the group from the user and add it to the dropdown.
                self.user.as_mut().unwrap().groups.retain(|g| g != &group);
            }
            Msg::OnError(e) => return Err(e),
            Msg::OnUserAddedToGroup(group) => {
                self.user.as_mut().unwrap().groups.push(group);
            }
        }
        Ok(true)
    }

    fn view_form(&self, u: &User) -> Html {
        html! {
                    <form ref=self.node_ref.clone() onsubmit=self.link.callback(|e: FocusEvent| { e.prevent_default(); Msg::SubmitUserUpdateForm })>
                      <div>
                        <span>{"User ID: "}</span>
                          <span>{&u.id}</span>
                      </div>
                      <div>
                        <label for="email">{"Email: "}</label>
                        <input type="text" id="email" value={u.email.clone()} />
                      </div>
                      <div>
                        <label for="display_name">{"Display name: "}</label>
                        <input type="text" id="display_name" value={u.display_name.clone()} />
                      </div>
                      <div>
                        <label for="first_name">{"First name: "}</label>
                        <input type="text" id="first_name" value={u.first_name.clone()} />
                      </div>
                      <div>
                        <label for="last_name">{"Last name: "}</label>
                        <input type="text" id="last_name" value={u.last_name.clone()} />
                      </div>
                      <div>
                        <span>{"Creation date: "}</span>
                        <span>{&u.creation_date.with_timezone(&chrono::Local)}</span>
                      </div>
                      <div>
                        <button type="submit">{"Update"}</button>
                      </div>
                    </form>
        }
    }
    fn view_messages(&self, error: &Option<Error>) -> Html {
        if self.update_successful {
            html! {
              <span>{"Update successful!"}</span>
            }
        } else if let Some(e) = error {
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
            let id = group.id;
            let display_name = group.display_name.clone();
            html! {
              <tr key="groupRow_".to_string() + &display_name.clone()>
                <td>{&group.display_name}</td>
                { if self.is_admin { html! {
                    <td><button onclick=self.link.callback(move |_| Msg::SubmitRemoveGroup(Group{id, display_name: display_name.clone()}))>{"-"}</button></td>
                  }} else { html!{} }
                }
              </tr>
            }
        };
        html! {
        <div>
          <span>{"Group memberships"}</span>
          <table>
            <tr key="headerRow">
              <th>{"Group"}</th>
              { if self.is_admin { html!{ <th></th> }} else { html!{} }}
            </tr>
            {u.groups.iter().map(make_group_row).collect::<Vec<_>>()}
            <tr key="groupToAddRow">
              {self.view_add_group_button(u)}
            </tr>
          </table>
        </div>
        }
    }

    fn view_add_group_button(&self, u: &User) -> Html {
        if self.is_admin {
            html! {
                <AddUserToGroupComponent
                    user=u.clone()
                    on_error=self.link.callback(Msg::OnError)
                    on_user_added_to_group=self.link.callback(Msg::OnUserAddedToGroup)/>
            }
        } else {
            html! {}
        }
    }
}

fn get_element(name: &str) -> Option<String> {
    use wasm_bindgen::JsCast;
    Some(
        web_sys::window()?
            .document()?
            .get_element_by_id(name)?
            .dyn_into::<web_sys::HtmlInputElement>()
            .ok()?
            .value(),
    )
}

fn get_element_or_empty(name: &str) -> String {
    get_element(name).unwrap_or_default()
}

impl Component for UserDetails {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut table = Self {
            link,
            username: props.username,
            node_ref: NodeRef::default(),
            _task: None,
            user: None,
            error: None,
            update_request: None,
            update_successful: false,
            is_admin: props.is_admin,
            group_to_remove: None,
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
                      {self.view_form(u)}
                      {self.view_messages(error)}
                      {self.view_group_memberships(u)}
                      <div>
                        <NavButton route=AppRoute::ChangePassword(self.username.clone())>{"Change password"}</NavButton>
                      </div>
                    </div>
                }
            }
        }
    }
}
