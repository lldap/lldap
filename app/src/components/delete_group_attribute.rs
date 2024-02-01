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
    query_path = "queries/delete_group_attribute.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteGroupAttributeQuery;

pub struct DeleteGroupAttribute {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteGroupAttributeProps {
    pub attribute_name: String,
    pub on_attribute_deleted: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteGroupAttribute,
    ConfirmDeleteGroupAttribute,
    DismissModal,
    DeleteGroupAttributeResponse(Result<delete_group_attribute_query::ResponseData>),
}

impl CommonComponent<DeleteGroupAttribute> for DeleteGroupAttribute {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteGroupAttribute => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmDeleteGroupAttribute => {
                self.update(ctx, Msg::DismissModal);
                self.common.call_graphql::<DeleteGroupAttributeQuery, _>(
                    ctx,
                    delete_group_attribute_query::Variables {
                        name: ctx.props().attribute_name.clone(),
                    },
                    Msg::DeleteGroupAttributeResponse,
                    "Error trying to delete group attribute",
                );
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::DeleteGroupAttributeResponse(response) => {
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

impl Component for DeleteGroupAttribute {
    type Message = Msg;
    type Properties = DeleteGroupAttributeProps;

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
            onclick={link.callback(|_| Msg::ClickedDeleteGroupAttribute)}>
            <i class="bi-x-circle-fill" aria-label="Delete attribute" />
          </button>
          {self.show_modal(ctx)}
          </>
        }
    }
}

impl DeleteGroupAttribute {
    fn show_modal(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
          <div
            class="modal fade"
            id={"deleteGroupAttributeModal".to_string() + &ctx.props().attribute_name}
            tabindex="-1"
            aria-labelledby="deleteGroupAttributeModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteGroupAttributeModalLabel">{"Delete group attribute?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                <span>
                  {"Are you sure you want to delete group attribute "}
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
                    onclick={link.callback(|_| Msg::ConfirmDeleteGroupAttribute)}
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
