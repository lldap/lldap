use crate::{
    components::router::{AppRoute, Link},
    infra::{
        api::HostService,
        common_component::{CommonComponent, CommonComponentParts},
    },
};
use anyhow::{bail, Result};
use validator_derive::Validate;
use yew::prelude::*;
use yew_form::Form;
use yew_form_derive::Model;

pub struct ResetPasswordStep1Form {
    common: CommonComponentParts<Self>,
    form: Form<FormModel>,
    just_succeeded: bool,
}

/// The fields of the form, with the constraints.
#[derive(Model, Validate, PartialEq, Eq, Clone, Default)]
pub struct FormModel {
    #[validate(length(min = 1, message = "Missing username"))]
    username: String,
}

pub enum Msg {
    Update,
    Submit,
    PasswordResetResponse(Result<()>),
}

impl CommonComponent<ResetPasswordStep1Form> for ResetPasswordStep1Form {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let FormModel { username } = self.form.model();
                self.common.call_backend(
                    ctx,
                    HostService::reset_password_step1(username),
                    Msg::PasswordResetResponse,
                );
                Ok(true)
            }
            Msg::PasswordResetResponse(response) => {
                response?;
                self.just_succeeded = true;
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ResetPasswordStep1Form {
    type Message = Msg;
    type Properties = ();

    fn create(_: &Context<Self>) -> Self {
        ResetPasswordStep1Form {
            common: CommonComponentParts::<Self>::create(),
            form: Form::<FormModel>::new(FormModel::default()),
            just_succeeded: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        self.just_succeeded = false;
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        type Field = yew_form::Field<FormModel>;
        let link = &ctx.link();
        html! {
            <form
              class="form center-block col-sm-4 col-offset-4">
                <div class="input-group">
                  <div class="input-group-prepend">
                    <span class="input-group-text">
                      <i class="bi-person-fill"/>
                    </span>
                  </div>
                  <Field
                    class="form-control"
                    class_invalid="is-invalid has-error"
                    class_valid="has-success"
                    form={&self.form}
                    field_name="username"
                    placeholder="Username or email"
                    autocomplete="username"
                    oninput={link.callback(|_| Msg::Update)} />
                </div>
                { if self.just_succeeded {
                    html! {
                      {"A reset token has been sent to your email."}
                    }
                } else {
                    html! {
                        <div class="form-group mt-3">
                          <button
                            type="submit"
                            class="btn btn-primary"
                            disabled={self.common.is_task_running()}
                            onclick={link.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})}>
                            <i class="bi-check-circle me-2"/>
                            {"Reset password"}
                          </button>
                          <Link
                            classes="btn-link btn"
                            disabled={self.common.is_task_running()}
                            to={AppRoute::Login}>
                            {"Back"}
                          </Link>
                        </div>
                    }
                }}
                <div class="form-group">
                { if let Some(e) = &self.common.error {
                    html! {
                      <div class="alert alert-danger mb-2">
                        {e.to_string() }
                      </div>
                    }
                  } else { html! {} }
                }
                </div>
            </form>
        }
    }
}
