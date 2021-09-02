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

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/update_user.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::graphql"
)]
pub struct UpdateUser;

pub struct UserDetails {
    link: ComponentLink<Self>,
    username: String,
    user: Option<User>,
    // Needed for the form.
    node_ref: NodeRef,
    // Error message displayed to the user.
    error: Option<anyhow::Error>,
    // The request, while we're waiting for the server to reply.
    update_request: Option<update_user::UpdateUserInput>,
    // True iff we just finished updating the user, to display a successful message.
    update_successful: bool,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    UserDetailsResponse(Result<get_user_details::ResponseData>),
    SubmitForm,
    UpdateFinished(Result<update_user::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub username: String,
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
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        self.update_successful = false;
        match msg {
            Msg::UserDetailsResponse(Ok(user)) => {
                self.user = Some(user.user);
            }
            Msg::UserDetailsResponse(Err(e)) => {
                self.error = Some(anyhow!("Error getting user details: {}", e));
                self.user = None;
            }
            Msg::SubmitForm => {
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
                return Ok(false);
            }
            Msg::UpdateFinished(r) => {
                match r {
                    Err(e) => return Err(e),
                    Ok(_) => {
                        ConsoleService::log("Successfully updated user");
                        self.update_successful = true;
                        let user = self.user.as_ref().unwrap();
                        let new_user = self.update_request.take().unwrap();
                        self.user = Some(User {
                            id: user.id.clone(),
                            email: new_user.email.unwrap_or_else(|| user.email.clone()),
                            display_name: new_user
                                .displayName
                                .unwrap_or_else(|| user.display_name.clone()),
                            first_name: new_user
                                .firstName
                                .unwrap_or_else(|| user.first_name.clone()),
                            last_name: new_user.lastName.unwrap_or_else(|| user.last_name.clone()),
                            creation_date: user.creation_date,
                        });
                    }
                };
            }
        }
        Ok(true)
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
    // The username.
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut table = UserDetails {
            link,
            username: props.username,
            node_ref: NodeRef::default(),
            _task: None,
            user: None,
            error: None,
            update_request: None,
            update_successful: false,
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
                    <form ref=self.node_ref.clone() onsubmit=self.link.callback(|e: FocusEvent| { e.prevent_default(); Msg::SubmitForm })>
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
                      { if self.update_successful {
                        html! {
                          <span>{"Update successful!"}</span>
                        }
                      } else if let Some(e) = error {
                        html! {
                          <div>
                            <span>{"Error: "}{e.to_string()}</span>
                          </div>
                        }
                      } else { html! {} }}
                    </form>
                }
            }
        }
    }
}
