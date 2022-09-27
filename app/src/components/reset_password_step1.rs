use crate::{
    components::router::{AppRoute, NavButton},
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
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::Update => Ok(true),
            Msg::Submit => {
                if !self.form.validate() {
                    bail!("Check the form for errors");
                }
                let FormModel { username } = self.form.model();
                self.common.call_backend(
                    HostService::reset_password_step1,
                    &username,
                    Msg::PasswordResetResponse,
                )?;
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

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        ResetPasswordStep1Form {
            common: CommonComponentParts::<Self>::create(props, link),
            form: Form::<FormModel>::new(FormModel::default()),
            just_succeeded: false,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        self.just_succeeded = false;
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        type Field = yew_form::Field<FormModel>;
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
                    form=&self.form
                    field_name="username"
                    placeholder="Username"
                    autocomplete="username"
                    oninput=self.common.callback(|_| Msg::Update) />
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
                            disabled=self.common.is_task_running()
                            onclick=self.common.callback(|e: MouseEvent| {e.prevent_default(); Msg::Submit})>
                            {"Reset password"}
                          </button>
                          <NavButton
                            classes="btn-link btn"
                            disabled=self.common.is_task_running()
                            route=AppRoute::Login>
                            {"Back"}
                          </NavButton>
                        </div>
                    }
                }}
                <div class="form-group">
                { if let Some(e) = &self.common.error {
                    html! {
                      <div class="alert alert-danger">
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
