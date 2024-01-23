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
    query_path = "queries/delete_user_attribute.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteUserAttributeQuery;

pub struct DeleteUserAttribute {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteUserAttributeProps {
    pub attribute_name: String,
    pub on_attribute_deleted: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteUserAttribute,
    ConfirmDeleteUserAttribute,
    DismissModal,
    DeleteUserAttributeResponse(Result<delete_user_attribute_query::ResponseData>),
}

impl CommonComponent<DeleteUserAttribute> for DeleteUserAttribute {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteUserAttribute => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmDeleteUserAttribute => {
                self.update(ctx, Msg::DismissModal);
                self.common.call_graphql::<DeleteUserAttributeQuery, _>(
                    ctx,
                    delete_user_attribute_query::Variables {
                        name: ctx.props().attribute_name.clone(),
                    },
                    Msg::DeleteUserAttributeResponse,
                    "Error trying to delete user attribute",
                );
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::DeleteUserAttributeResponse(response) => {
                response?;
                ctx.props()
                    .on_attribute_deleted
                    .emit(ctx.props().attribute_name.clone());
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for DeleteUserAttribute {
    type Message = Msg;
    type Properties = DeleteUserAttributeProps;

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
            class="btn btn-danger"
            disabled={self.common.is_task_running()}
            onclick={link.callback(|_| Msg::ClickedDeleteUserAttribute)}>
            <i class="bi-x-circle-fill" aria-label="Delete attribute" />
          </button>
          {self.show_modal(ctx)}
          </>
        }
    }
}

impl DeleteUserAttribute {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <div
            class="modal fade"
            id={"deleteUserAttributeModal".to_string() + &ctx.props().attribute_name}
            tabindex="-1"
            aria-labelledby="deleteUserAttributeModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteUserAttributeModalLabel">{"Delete user attribute?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                <span>
                  {"Are you sure you want to delete user attribute "}
                  <b>{&ctx.props().attribute_name}</b>{"?"}
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
                    onclick={link.callback(|_| Msg::ConfirmDeleteUserAttribute)}
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
