use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    modal::Modal,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/reset_user_mfa.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ResetUserMfa;

pub struct ResetMfa {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct ResetMfaProps {
    pub username: String,
    pub disabled: bool,
    pub on_mfa_reset: Callback<()>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedResetMfa,
    ConfirmResetMfa,
    DismissModal,
    ResetMfaResponse(Result<reset_user_mfa::ResponseData>),
}

impl CommonComponent<ResetMfa> for ResetMfa {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedResetMfa => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmResetMfa => {
                self.update(ctx, Msg::DismissModal);
                self.common.call_graphql::<ResetUserMfa, _>(
                    ctx,
                    reset_user_mfa::Variables {
                        user: ctx.props().username.clone(),
                    },
                    Msg::ResetMfaResponse,
                    "Error trying to reset the user's two-factor authentication",
                );
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::ResetMfaResponse(response) => {
                response?;
                ctx.props().on_mfa_reset.emit(());
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for ResetMfa {
    type Message = Msg;
    type Properties = ResetMfaProps;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            node_ref: NodeRef::default(),
            modal: None,
        }
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
        CommonComponentParts::<Self>::update_and_report_error(
            self,
            ctx,
            msg,
            ctx.props().on_error.clone(),
        )
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <>
          <button
            class="btn btn-danger me-2"
            disabled={ctx.props().disabled || self.common.is_task_running()}
            onclick={link.callback(|_| Msg::ClickedResetMfa)}>
            <i class="bi-shield-x me-2"></i>
            {"Reset two-factor"}
          </button>
          {self.show_modal(ctx)}
          </>
        }
    }
}

impl ResetMfa {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <div
            class="modal fade"
            id={"resetMfaModal".to_string() + &ctx.props().username}
            tabindex="-1"
            aria-labelledby="resetMfaModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="resetMfaModalLabel">{"Reset two-factor authentication?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                <span>
                  {"User "}
                  <b>{&ctx.props().username}</b>
                  {" will sign in with their password alone until they enroll again."}
                </span>
                </div>
                <div class="modal-footer">
                  <button
                    type="button"
                    class="btn btn-secondary"
                    onclick={link.callback(|_| Msg::DismissModal)}>
                    <i class="bi-x-circle me-2"></i>
                    {"Cancel"}
                  </button>
                  <button
                    type="button"
                    onclick={link.callback(|_| Msg::ConfirmResetMfa)}
                    class="btn btn-danger">
                    <i class="bi-check-circle me-2"></i>
                    {"Yes, I'm sure"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
