use crate::infra::{
    api::{hash_password, HostService, PasswordHash, PasswordWasLeaked},
    common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::Result;
use gloo_timers::callback::Timeout;
use web_sys::{HtmlInputElement, InputEvent};
use yew::{html, Callback, Classes, Component, Context, Properties};
use yew_form::{Field, Form, Model};

pub enum PasswordFieldMsg {
    OnInput(String),
    OnInputIdle,
    PasswordCheckResult(Result<(Option<PasswordWasLeaked>, PasswordHash)>),
}

#[derive(PartialEq)]
pub enum PasswordState {
    // Whether the password was found in a leak.
    Checked(PasswordWasLeaked),
    // Server doesn't support checking passwords (TODO: move to config).
    NotSupported,
    // Requested a check, no response yet from the server.
    Loading,
    // User is still actively typing.
    Typing,
}

pub struct PasswordField<FormModel: Model> {
    common: CommonComponentParts<Self>,
    timeout_task: Option<Timeout>,
    password: String,
    password_check_state: PasswordState,
    _marker: std::marker::PhantomData<FormModel>,
}

impl<FormModel: Model> CommonComponent<PasswordField<FormModel>> for PasswordField<FormModel> {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> anyhow::Result<bool> {
        match msg {
            PasswordFieldMsg::OnInput(password) => {
                self.password = password;
                if self.password_check_state != PasswordState::NotSupported {
                    self.password_check_state = PasswordState::Typing;
                    if self.password.len() >= 8 {
                        let link = ctx.link().clone();
                        self.timeout_task = Some(Timeout::new(500, move || {
                            link.send_message(PasswordFieldMsg::OnInputIdle)
                        }));
                    }
                }
            }
            PasswordFieldMsg::PasswordCheckResult(result) => {
                self.timeout_task = None;
                // If there's an error from the backend, don't retry.
                self.password_check_state = PasswordState::NotSupported;
                if let (Some(check), hash) = result? {
                    if hash == hash_password(&self.password) {
                        self.password_check_state = PasswordState::Checked(check)
                    }
                }
            }
            PasswordFieldMsg::OnInputIdle => {
                self.timeout_task = None;
                if self.password_check_state != PasswordState::NotSupported {
                    self.password_check_state = PasswordState::Loading;
                    self.common.call_backend(
                        ctx,
                        HostService::check_password_haveibeenpwned(hash_password(&self.password)),
                        PasswordFieldMsg::PasswordCheckResult,
                    );
                }
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<PasswordField<FormModel>> {
        &mut self.common
    }
}

#[derive(Properties, PartialEq, Clone)]
pub struct PasswordFieldProperties<FormModel: Model> {
    pub field_name: String,
    pub form: Form<FormModel>,
    #[prop_or_else(|| { "form-control".into() })]
    pub class: Classes,
    #[prop_or_else(|| { "is-invalid".into() })]
    pub class_invalid: Classes,
    #[prop_or_else(|| { "is-valid".into() })]
    pub class_valid: Classes,
    #[prop_or_else(Callback::noop)]
    pub oninput: Callback<String>,
}

impl<FormModel: Model> Component for PasswordField<FormModel> {
    type Message = PasswordFieldMsg;
    type Properties = PasswordFieldProperties<FormModel>;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            timeout_task: None,
            password: String::new(),
            password_check_state: PasswordState::Typing,
            _marker: std::marker::PhantomData,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> yew::Html {
        let link = &ctx.link();
        html! {
          <div>
            <Field<FormModel>
                autocomplete={"new-password"}
                input_type={"password"}
                field_name={ctx.props().field_name.clone()}
                form={ctx.props().form.clone()}
                class={ctx.props().class.clone()}
                class_invalid={ctx.props().class_invalid.clone()}
                class_valid={ctx.props().class_valid.clone()}
                oninput={link.callback(|e: InputEvent| {
                    use wasm_bindgen::JsCast;
                    let target = e.target().unwrap();
                    let input = target.dyn_into::<HtmlInputElement>().unwrap();
                    PasswordFieldMsg::OnInput(input.value())
                })} />
            {
                match self.password_check_state {
                    PasswordState::Checked(PasswordWasLeaked(true)) => html! { <i class="bi bi-x"></i> },
                    PasswordState::Checked(PasswordWasLeaked(false)) => html! { <i class="bi bi-check"></i> },
                    PasswordState::NotSupported | PasswordState::Typing => html!{},
                    PasswordState::Loading =>
                        html! {
                          <div class="spinner-border spinner-border-sm" role="status">
                            <span class="sr-only">{"Loading..."}</span>
                          </div>
                        },
                }
            }
          </div>
        }
    }
}
