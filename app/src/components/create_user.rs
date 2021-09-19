use crate::infra::api::HostService;
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
    custom_scalars_module = "crate::infra::graphql"
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
                    user: create_user::CreateUserInput {
                        id: get_element("username")
                            .filter(not_empty)
                            .ok_or_else(|| anyhow!("Missing username"))?,
                        email: get_element("email")
                            .filter(not_empty)
                            .ok_or_else(|| anyhow!("Missing email"))?,
                        displayName: get_element("display-name").filter(not_empty),
                        firstName: get_element("first-name").filter(not_empty),
                        lastName: get_element("last-name").filter(not_empty),
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
            <>
            <form
              class="form"
              ref=self.node_ref.clone()
              onsubmit=self.link.callback(|e: FocusEvent| { e.prevent_default(); Msg::SubmitForm })>
              <div class="form-group row">
                <label for="username"
                  class="form-label col-sm-2 col-form-label">
                  {"User name*:"}
                </label>
                <div class="col-sm-10">
                  <input
                    type="text"
                    id="username"
                    class="form-control"
                    autocomplete="username"
                    required=true />
                </div>
              </div>
              <div class="form-group row">
                <label for="email"
                  class="form-label col-sm-2 col-form-label">
                  {"Email*:"}
                </label>
                <div class="col-sm-10">
                  <input
                    type="email"
                    id="email"
                    class="form-control"
                    autocomplete="email"
                    required=true />
                </div>
              </div>
              <div class="form-group row">
                <label for="display-name"
                  class="form-label col-sm-2 col-form-label">
                  {"Display name*:"}
                </label>
                <div class="col-sm-10">
                  <input
                    type="text"
                    autocomplete="name"
                    class="form-control"
                    id="display-name" />
                  </div>
              </div>
              <div class="form-group row">
                <label for="first-name"
                  class="form-label col-sm-2 col-form-label">
                  {"First name:"}
                </label>
                <div class="col-sm-10">
                  <input
                    type="text"
                    autocomplete="given-name"
                    class="form-control"
                    id="first-name" />
                </div>
              </div>
              <div class="form-group row">
                <label for="last-name"
                  class="form-label col-sm-2 col-form-label">
                  {"Last name:"}
                </label>
                <div class="col-sm-10">
                  <input
                    type="text"
                    autocomplete="family-name"
                    class="form-control"
                    id="last-name" />
                </div>
              </div>
              <div class="form-group row">
                <label for="password"
                  class="form-label col-sm-2 col-form-label">
                  {"Password:"}
                </label>
                <div class="col-sm-10">
                  <input
                    type="password"
                    id="password"
                    class="form-control"
                    autocomplete="new-password"
                    minlength="8" />
                </div>
              </div>
              <div class="form-group row">
                <button
                  class="btn btn-primary col-sm-1 col-form-label"
                  type="submit">{"Submit"}</button>
              </div>
            </form>
            { if let Some(e) = &self.error {
                html! {
                  <div class="alert alert-danger">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            </>
        }
    }
}
