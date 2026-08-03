use crate::{
    components::{
        form::submit::Submit,
        router::{AppRoute, Link},
    },
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
        cookies::{delete_cookie, get_cookie},
        modal::Modal,
    },
};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use gloo_timers::callback::Timeout;
use graphql_client::GraphQLQuery;
use lldap_mfa::{TOTP_ENROLLMENT_EXPIRED, TOTP_ENROLLMENT_TTL_SECS, split_totp_suffix};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/start_mfa_enrollment.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct StartMfaEnrollment;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/finish_mfa_enrollment.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct FinishMfaEnrollment;

#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct ConfirmationModel {
    #[validate(custom(
        function = "has_combined_shape",
        message = "Enter your password, a ':' and the current 6-digit code"
    ))]
    combined: String,
}

fn has_combined_shape(value: &str) -> Result<(), validator::ValidationError> {
    match split_totp_suffix(value) {
        Some((password, _)) if !password.is_empty() => Ok(()),
        _ => Err(validator::ValidationError::new("")),
    }
}

fn spaced_groups(secret: &str) -> String {
    secret
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

struct EnrollmentData {
    secret_base32: String,
    state: String,
    qr_data_uri: String,
    seed: Vec<u8>,
}

enum Phase {
    Loading,
    InProgress(EnrollmentData),
    Complete,
}

enum CodeHint {
    None,
    Valid,
    Invalid,
}

pub struct RegisterMfa {
    common: CommonComponentParts<Self>,
    form: Form<ConfirmationModel>,
    phase: Phase,
    hint: CodeHint,
    mfa_exempt: bool,
    expiry_timer: Option<Timeout>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub username: String,
    pub enrollment_required: bool,
    pub on_enrolled: Callback<()>,
    pub on_logged_out: Callback<()>,
}

pub enum Msg {
    EnrollmentStartResponse(Result<start_mfa_enrollment::ResponseData>),
    Update,
    Submit,
    EnrollmentFinishResponse(Result<finish_mfa_enrollment::ResponseData>),
    EnrollmentExpired,
    ExpiredLogoutRequested,
    ExpiredLogoutCompleted(Result<()>),
}

impl CommonComponent<RegisterMfa> for RegisterMfa {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::EnrollmentStartResponse(res) => {
                let start = res?.start_mfa_enrollment;
                let qr_svg = qrcode::QrCode::new(start.otpauth_uri.as_bytes())
                    .map_err(|e| anyhow!("Could not render the QR code: {}", e))?
                    .render::<qrcode::render::svg::Color>()
                    .min_dimensions(200, 200)
                    .build();
                let qr_data_uri = format!(
                    "data:image/svg+xml;base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(&qr_svg)
                );
                let seed = lldap_mfa::seed_from_base32(&start.secret_base32)
                    .map_err(|_| anyhow!("Invalid secret received from the server"))?;
                self.phase = Phase::InProgress(EnrollmentData {
                    secret_base32: start.secret_base32,
                    state: start.state,
                    qr_data_uri,
                    seed,
                });
                Ok(true)
            }
            Msg::Update => {
                let combined = self.form.field_value("combined");
                self.hint = match (&self.phase, split_totp_suffix(&combined)) {
                    (Phase::InProgress(data), Some((_, code))) => {
                        let now_secs = (js_sys::Date::now() / 1000.0) as u64;
                        match lldap_mfa::totp_verify(&data.seed, code, now_secs) {
                            Ok(true) => CodeHint::Valid,
                            _ => CodeHint::Invalid,
                        }
                    }
                    _ => CodeHint::None,
                };
                Ok(true)
            }
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let Phase::InProgress(data) = &self.phase else {
                    bail!("No enrollment in progress");
                };
                let combined = self.form.field_value("combined");
                let (_, code) =
                    split_totp_suffix(&combined).expect("The validator checked the shape");
                self.common.call_graphql::<FinishMfaEnrollment, _>(
                    ctx,
                    finish_mfa_enrollment::Variables {
                        state: data.state.clone(),
                        code: code.to_owned(),
                    },
                    Msg::EnrollmentFinishResponse,
                    "Error enabling two-factor authentication",
                );
                Ok(true)
            }
            Msg::EnrollmentFinishResponse(res) => match res {
                Ok(_) => {
                    if let Some(timer) = self.expiry_timer.take() {
                        timer.cancel();
                    }
                    self.phase = Phase::Complete;
                    ctx.props().on_enrolled.emit(());
                    Ok(true)
                }
                Err(e) if e.to_string().contains(TOTP_ENROLLMENT_EXPIRED) => {
                    self.modal.as_ref().expect("modal not initialized").show();
                    Ok(true)
                }
                Err(e) => Err(e),
            },
            Msg::EnrollmentExpired => {
                if matches!(self.phase, Phase::InProgress(_)) {
                    self.modal.as_ref().expect("modal not initialized").show();
                }
                Ok(true)
            }
            Msg::ExpiredLogoutRequested => {
                self.common
                    .call_backend(ctx, HostService::logout(), Msg::ExpiredLogoutCompleted);
                Ok(true)
            }
            Msg::ExpiredLogoutCompleted(res) => {
                res?;
                self.modal.as_ref().expect("modal not initialized").hide();
                delete_cookie("user_id")?;
                ctx.props().on_logged_out.emit(());
                Ok(false)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for RegisterMfa {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let link = ctx.link().clone();
        let mut component = RegisterMfa {
            common: CommonComponentParts::<Self>::create(),
            form: Form::<ConfirmationModel>::new(ConfirmationModel::default()),
            phase: Phase::Loading,
            hint: CodeHint::None,
            mfa_exempt: get_cookie("mfa_exempt").ok().flatten().as_deref() == Some("true"),
            expiry_timer: Some(Timeout::new(
                (TOTP_ENROLLMENT_TTL_SECS * 1000) as u32,
                move || link.send_message(Msg::EnrollmentExpired),
            )),
            node_ref: NodeRef::default(),
            modal: None,
        };
        component.common.call_graphql::<StartMfaEnrollment, _>(
            ctx,
            start_mfa_enrollment::Variables {},
            Msg::EnrollmentStartResponse,
            "Error starting two-factor enrollment",
        );
        component
    }

    fn rendered(&mut self, _: &Context<Self>, first_render: bool) {
        if first_render {
            self.modal = Some(Modal::new(
                self.node_ref
                    .cast::<web_sys::Element>()
                    .expect("Modal node is not an element"),
            ));
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
          <>
            <div class="mb-2 mt-2">
              <h5 class="fw-bold text-center">
                {"Set up two-factor authentication"}
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
            { match &self.phase {
                Phase::Loading => html! {
                  <div>
                    <img src={"spinner.gif"} alt={"Loading"} />
                  </div>
                },
                Phase::InProgress(data) => self.view_enrollment(ctx, data),
                Phase::Complete => self.view_complete(ctx),
            }}
            {self.expiry_modal(ctx)}
          </>
        }
    }
}

impl RegisterMfa {
    fn view_enrollment(&self, ctx: &Context<Self>, data: &EnrollmentData) -> Html {
        type Field = yew_form::Field<ConfirmationModel>;
        let link = ctx.link();
        html! {
          <>
            <p class="text-center">
              {"Scan the QR code with an authenticator app (or enter the secret manually):"}
            </p>
            <p class="text-center">
              <img
                src={data.qr_data_uri.clone()}
                width="200"
                height="200"
                alt="TOTP QR code" />
            </p>
            <p class="text-center">
              <code>{spaced_groups(&data.secret_base32)}</code>
            </p>
            <div class="mx-auto" style="max-width: 720px">
            { if self.mfa_exempt {
                html! {
                  <div class="alert alert-warning">
                    {"You are in lldap_mfa_disabled, so you will not be asked for a code at login until you leave the group."}
                  </div>
                }
              } else {
                html! {
                  <p>
                    {"After enrolling, sign in with your password, a colon, and your two-factor code."}
                  </p>
                }
              }}
            <p>
              {"Verify by confirming with your password, ':' and the current code: "}
              <code>{"yourpassword:123456"}</code>
            </p>
            <form class="form">
              <div class="mx-auto" style="max-width: 410px">
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
                    oninput={link.callback(|_| Msg::Update)} />
                  <div class="invalid-feedback">
                    {self.form.field_message("combined")}
                  </div>
                </div>
                <div class="mb-3 mt-1">
                  { match self.hint {
                      CodeHint::None => html! {},
                      CodeHint::Valid => html! {
                        <div class="text-success">
                          <i class="bi-check-circle me-2"></i>
                          {"The code matches."}
                        </div>
                      },
                      CodeHint::Invalid => html! {
                        <div class="text-danger">
                          <i class="bi-x-circle me-2"></i>
                          {"This code does not match yet."}
                        </div>
                      },
                  }}
                </div>
              </div>
              <Submit
                text="Enable two-factor"
                disabled={self.common.is_task_running()}
                onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}>
                { if ctx.props().enrollment_required { html! {} } else { html! {
                  <Link
                    classes="btn btn-secondary ms-2 col-auto col-form-label"
                    to={AppRoute::UserDetails{user_id: ctx.props().username.clone()}}>
                    <i class="bi-arrow-return-left me-2"></i>
                    {"Back"}
                  </Link>
                }}}
              </Submit>
            </form>
            </div>
          </>
        }
    }

    fn view_complete(&self, ctx: &Context<Self>) -> Html {
        html! {
          <>
            <div class="alert alert-success mt-4">
              {"Two-factor authentication is enabled."}
            </div>
            <Link
              classes="btn btn-primary"
              to={AppRoute::UserDetails{user_id: ctx.props().username.clone()}}>
              <i class="bi-arrow-return-left me-2"></i>
              {"Back to profile"}
            </Link>
          </>
        }
    }

    fn expiry_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <div
            class="modal fade"
            id="mfaEnrollmentExpiredModal"
            tabindex="-1"
            aria-labelledby="mfaEnrollmentExpiredModalLabel"
            aria-hidden="true"
            data-bs-backdrop="static"
            data-bs-keyboard="false"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="mfaEnrollmentExpiredModalLabel">{"Enrollment session expired"}</h5>
                </div>
                <div class="modal-body">
                  <span>
                    {"This page has expired. Log in again to continue setting up two-factor authentication."}
                  </span>
                </div>
                <div class="modal-footer">
                  <button
                    type="button"
                    class="btn btn-primary"
                    disabled={self.common.is_task_running()}
                    onclick={link.callback(|_| Msg::ExpiredLogoutRequested)}>
                    <i class="bi-box-arrow-right me-2"></i>
                    {"Log in again"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
