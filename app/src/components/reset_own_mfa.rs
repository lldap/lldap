use crate::{
    components::{
        form::submit::Submit,
        register_mfa::has_combined_shape,
        router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{Result, anyhow, bail};
use gloo_console::error;
use graphql_client::GraphQLQuery;
use lldap_auth::{login, opaque::client::login as opaque_login};
use lldap_mfa::split_totp_suffix;
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;
use yew_router::{prelude::History, scope_ext::RouterScopeExt};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reset_own_mfa.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ResetOwnMfa;

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(custom(
        function = "has_combined_shape",
        message = "Enter your password, a ':' and the current 6-digit code"
    ))]
    combined: String,
}

pub struct ResetOwnMfaForm {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    opaque_data: Option<(opaque_login::ClientLogin, String)>,
}

#[derive(Clone, PartialEq, Eq, Properties)]
pub struct Props {
    pub username: String,
}

pub enum Msg {
    FormUpdate,
    Submit,
    AuthenticationStartResponse(Result<Box<login::ServerLoginStartResponse>>),
    ResetResponse(Result<reset_own_mfa::ResponseData>),
}

impl CommonComponent<ResetOwnMfaForm> for ResetOwnMfaForm {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::FormUpdate => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let combined = self.form.field_value("combined");
                let Some((password, code)) = split_totp_suffix(&combined) else {
                    bail!("Check the form for errors");
                };
                let mut rng = rand::rngs::OsRng;
                let login_start = opaque_login::start_login(password, &mut rng)
                    .map_err(|e| anyhow!("Could not initialize login: {}", e))?;
                // Keep the submitted code: the field stays editable while the login is in flight.
                self.opaque_data = Some((login_start.state, code.to_owned()));
                self.common.call_backend(
                    ctx,
                    HostService::login_start(login::ClientLoginStartRequest {
                        username: ctx.props().username.clone().into(),
                        login_start_request: login_start.message,
                    }),
                    Msg::AuthenticationStartResponse,
                );
                Ok(true)
            }
            Msg::AuthenticationStartResponse(res) => {
                let res = res.map_err(|e| anyhow!("Could not initiate login: {}", e))?;
                let (login, code) = self.opaque_data.take().expect("Missing login data");
                opaque_login::finish_login(login, res.credential_response).map_err(|e| {
                    error!(&format!("Invalid password: {}", e));
                    anyhow!("Invalid password")
                })?;
                self.common.call_graphql::<ResetOwnMfa, _>(
                    ctx,
                    reset_own_mfa::Variables { code },
                    Msg::ResetResponse,
                    "Error resetting two-factor authentication",
                );
                Ok(true)
            }
            Msg::ResetResponse(res) => {
                res?;
                ctx.link().history().unwrap().push(AppRoute::UserDetails {
                    user_id: ctx.props().username.clone(),
                });
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ResetOwnMfaForm {
    type Message = Msg;
    type Properties = Props;

    fn create(_: &Context<Self>) -> Self {
        ResetOwnMfaForm {
            common: CommonComponentParts::<Self>::create(),
            form: Form::<FormModel>::new(FormModel::default()),
            opaque_data: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<FormModel>;
        let link = ctx.link();
        html! {
          <>
            <div class="mb-2 mt-2">
              <h5 class="fw-bold text-center">
                {"Reset two-factor authentication"}
              </h5>
            </div>
            {
              if let Some(e) = &self.common.error {
                html! {
                  <div class="alert alert-danger mt-3 mb-3">
                    {e.to_string() }
                  </div>
                }
              } else { html! {} }
            }
            <div class="mx-auto" style="max-width: 410px">
              <p>
                {"You will sign in with your password alone until you enroll again."}
              </p>
              <p>
                {"Confirm with your password, ':' and the current code: "}
                <code>{"yourpassword:123456"}</code>
              </p>
              <form class="form">
                <label for="combined" class="form-label">
                  {"Password and code"}
                  <span class="text-danger">{"*"}</span>
                  {":"}
                </label>
                <div class="input-group">
                  <div class="input-group-prepend">
                    <span class="input-group-text">
                      <i class="bi-lock-fill"/>
                    </span>
                  </div>
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form={&self.form}
                    field_name="combined"
                    input_type="password"
                    autocomplete="off"
                    oninput={link.callback(|_| Msg::FormUpdate)} />
                  <div class="invalid-feedback">
                    {self.form.field_message("combined")}
                  </div>
                </div>
                <Submit
                  text="Reset two-factor"
                  disabled={self.common.is_task_running()}
                  onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}>
                  <Link
                    classes="btn btn-secondary ms-2 col-auto col-form-label"
                    to={AppRoute::UserDetails{user_id: ctx.props().username.clone()}}>
                    <i class="bi-arrow-return-left me-2"></i>
                    {"Back"}
                  </Link>
                </Submit>
              </form>
            </div>
          </>
        }
    }
}
