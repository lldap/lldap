use crate::api::HostService;
use anyhow::{anyhow, Context, Result};
use graphql_client::GraphQLQuery;
use lldap_auth::{opaque, registration};
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::graphql"
)]
pub struct CreateUser;

pub struct CreateUserForm {
    link: ComponentLink<Self>,
    route_dispatcher: RouteAgentDispatcher,
    node_ref: NodeRef,
    error: Option<anyhow::Error>,
    registration_start: Option<opaque::client::registration::ClientRegistration>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    CreateUserResponse(Result<create_user::ResponseData>),
    SubmitForm,
    SuccessfulCreation,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
}

#[allow(clippy::ptr_arg)]
fn not_empty(s: &String) -> bool {
    !s.is_empty()
}

impl CreateUserForm {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<()> {
        match msg {
            Msg::SubmitForm => {
                let req = create_user::Variables {
                    user: create_user::UserInput {
                        id: get_element("username")
                            .filter(not_empty)
                            .ok_or_else(|| anyhow!("Missing username"))?,
                        email: get_element("email")
                            .filter(not_empty)
                            .ok_or_else(|| anyhow!("Missing email"))?,
                        displayName: get_element("displayname").filter(not_empty),
                        firstName: get_element("firstname").filter(not_empty),
                        lastName: get_element("lastname").filter(not_empty),
                    },
                };
                self._task = Some(HostService::graphql_query::<CreateUser>(
                    req,
                    self.link.callback(Msg::CreateUserResponse),
                    "Error trying to create user",
                )?);
            }
            Msg::CreateUserResponse(r) => {
                match r {
                    Err(e) => return Err(e),
                    Ok(r) => ConsoleService::log(&format!(
                        "Created user '{}' at '{}'",
                        &r.create_user.id, &r.create_user.creation_date
                    )),
                };
                let user_id = get_element("username")
                    .filter(not_empty)
                    .ok_or_else(|| anyhow!("Missing username"))?;
                if let Some(password) = get_element("password").filter(not_empty) {
                    // User was successfully created, let's register the password.
                    let mut rng = rand::rngs::OsRng;
                    let client_registration_start =
                        opaque::client::registration::start_registration(&password, &mut rng)?;
                    self.registration_start = Some(client_registration_start.state);
                    let req = registration::ClientRegistrationStartRequest {
                        username: user_id,
                        registration_start_request: client_registration_start.message,
                    };
                    self._task = Some(
                        HostService::register_start(
                            req,
                            self.link.callback(Msg::RegistrationStartResponse),
                        )
                        .context("Error trying to create user")?,
                    );
                } else {
                    self.update(Msg::SuccessfulCreation);
                }
            }
            Msg::RegistrationStartResponse(response) => {
                debug_assert!(self.registration_start.is_some());
                let response = response?;
                let mut rng = rand::rngs::OsRng;
                let registration_upload = opaque::client::registration::finish_registration(
                    self.registration_start.take().unwrap(),
                    response.registration_response,
                    &mut rng,
                )?;
                let req = registration::ClientRegistrationFinishRequest {
                    server_data: response.server_data,
                    registration_upload: registration_upload.message,
                };
                self._task = Some(
                    HostService::register_finish(
                        req,
                        self.link.callback(Msg::RegistrationFinishResponse),
                    )
                    .context("Error trying to register user")?,
                );
            }
            Msg::RegistrationFinishResponse(response) => {
                if response.is_err() {
                    return response;
                }
                self.update(Msg::SuccessfulCreation);
            }
            Msg::SuccessfulCreation => {
                self.route_dispatcher
                    .send(RouteRequest::ChangeRoute(Route::new_no_state(
                        "/list_users",
                    )));
            }
        }
        Ok(())
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

impl Component for CreateUserForm {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            route_dispatcher: RouteAgentDispatcher::new(),
            node_ref: NodeRef::default(),
            error: None,
            registration_start: None,
            _task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.error = None;
        if let Err(e) = self.handle_msg(msg) {
            ConsoleService::error(&e.to_string());
            self.error = Some(e);
        }
        true
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <form ref=self.node_ref.clone() onsubmit=self.link.callback(|e: FocusEvent| { e.prevent_default(); Msg::SubmitForm })>
                <div>
                    <label for="username">{"User name:"}</label>
                    <input type="text" id="username" />
                </div>
                <div>
                    <label for="email">{"Email:"}</label>
                    <input type="text" id="email" />
                </div>
                <div>
                    <label for="displayname">{"Display name:"}</label>
                    <input type="text" id="displayname" />
                </div>
                <div>
                    <label for="firstname">{"First name:"}</label>
                    <input type="text" id="firstname" />
                </div>
                <div>
                    <label for="lastname">{"Last name:"}</label>
                    <input type="text" id="lastname" />
                </div>
                <div>
                    <label for="password">{"Password:"}</label>
                    <input type="password" id="password" />
                </div>
                <button type="submit">{"Submit"}</button>
                <div>
                { if let Some(e) = &self.error {
                    html! { e.to_string() }
                  } else { html! {} }
                }
                </div>
            </form>
        }
    }
}
