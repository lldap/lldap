use crate::{
    components::router::AppRoute,
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{bail, Context, Result};
use lldap_auth::{
    opaque::client::registration as opaque_registration,
    password_reset::ServerPasswordResetResponse, registration,
};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
};

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 8, message = "Invalid password. Min length: 8"))]
    password: String,
    #[validate(must_match(other = "password", message = "Passwords must match"))]
    confirm_password: String,
}

pub struct ResetPasswordStep2Form {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    username: Option<String>,
    opaque_data: Option<opaque_registration::ClientRegistration>,
    route_dispatcher: RouteAgentDispatcher,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub token: String,
}

pub enum Msg {
    ValidateTokenResponse(Result<ServerPasswordResetResponse>),
    FormUpdate,
    Submit,
    RegistrationStartResponse(Result<Box<registration::ServerRegistrationStartResponse>>),
    RegistrationFinishResponse(Result<()>),
}

impl CommonComponent<ResetPasswordStep2Form> for ResetPasswordStep2Form {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ValidateTokenResponse(response) => {
                self.username = Some(response?.user_id);
                self.common.cancel_task();
                Ok(true)
            }
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let mut rng = rand::rngs::OsRng;
                let new_password = self.form.model().password;
                let registration_start_request =
                    opaque_registration::start_registration(&new_password, &mut rng)
                        .context("Could not initiate password change")?;
                let req = registration::ClientRegistrationStartRequest {
                    username: self.username.clone().unwrap(),
                    registration_start_request: registration_start_request.message,
                };
                self.opaque_data = Some(registration_start_request.state);
                self.common.call_backend(
                    HostService::register_start,
                    req,
                    Msg::RegistrationStartResponse,
                )?;
                Ok(true)
            }
            Msg::RegistrationStartResponse(res) => {
                let res = res.context("Could not initiate password change")?;
                let registration = self.opaque_data.take().expect("Missing registration data");
                let mut rng = rand::rngs::OsRng;
                let registration_finish = opaque_registration::finish_registration(
                    registration,
                    res.registration_response,
                    &mut rng,
                )
                .context("Error during password change")?;
                let req = registration::ClientRegistrationFinishRequest {
                    server_data: res.server_data,
                    registration_upload: registration_finish.message,
                };
                self.common.call_backend(
                    HostService::register_finish,
                    req,
                    Msg::RegistrationFinishResponse,
                )?;
                Ok(false)
            }
            Msg::RegistrationFinishResponse(response) => {
                self.common.cancel_task();
                if response.is_ok() {
                    self.route_dispatcher
                        .send(RouteRequest::ChangeRoute(Route::from(AppRoute::Login)));
                }
                response?;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ResetPasswordStep2Form {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut component = ResetPasswordStep2Form {
            common: CommonComponentParts::<Self>::create(props, link),
            form: yew_form::Form::<FormModel>::new(FormModel::default()),
            opaque_data: None,
            route_dispatcher: RouteAgentDispatcher::new(),
            username: None,
        };
        let token = component.common.token.clone();
        component
            .common
            .call_backend(
                HostService::reset_password_step2,
                &token,
                Msg::ValidateTokenResponse,
            )
            .unwrap();
        component
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        match (&self.username, &self.common.error) {
            (None, None) => {
                return html! {
                  {"Validating token"}
                }
            }
            (None, Some(e)) => {
                return html! {
                  <div class="alert alert-danger">
                    {e.to_string() }
                  </div>
                }
            }
            _ => (),
        };
        type Field = yew_form::Field<FormModel>;
        html! {
          <>
            <h2>{"Reset your password"}</h2>
            <form
              class="form">
              <div class="form-group row">
                <label for="new_password"
                  class="form-label col-sm-2 col-form-label">
                  {"New password*:"}
                </label>
                <div class="col-sm-10">
                  <Field
                    form=&self.form
                    field_name="password"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="new-password"
                    input_type="password"
                    oninput=self.common.callback(|_| Msg::FormUpdate) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("password")}
                  </div>
                </div>
              </div>
              <div class="form-group row">
                <label for="confirm_password"
                  class="form-label col-sm-2 col-form-label">
                  {"Confirm password*:"}
                </label>
                <div class="col-sm-10">
                  <Field
                    form=&self.form
                    field_name="confirm_password"
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    autocomplete="new-password"
                    input_type="password"
                    oninput=self.common.callback(|_| Msg::FormUpdate) />
                  <div class="invalid-feedback">
                    {&self.form.field_message("confirm_password")}
                  </div>
                </div>
              </div>
              <div class="form-group row mt-2">
                <button
                  class="btn btn-primary col-sm-1 col-form-label"
                  type="submit"
                  disabled=self.common.is_task_running()
                  onclick=self.common.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})>
                  {"Submit"}
                </button>
              </div>
            </form>
            { if let Some(e) = &self.common.error {
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
