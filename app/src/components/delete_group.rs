use crate::{
    components::group_table::Group,
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        modal::Modal,
    },
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteGroupQuery;

pub struct DeleteGroup {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteGroupProps {
    pub group: Group,
    pub on_group_deleted: Callback<i64>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteGroup,
    ConfirmDeleteGroup,
    DismissModal,
    DeleteGroupResponse(Result<delete_group_query::ResponseData>),
}

impl CommonComponent<DeleteGroup> for DeleteGroup {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteGroup => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmDeleteGroup => {
                self.update(Msg::DismissModal);
                self.common.call_graphql::<DeleteGroupQuery, _>(
                    delete_group_query::Variables {
                        group_id: self.common.group.id,
                    },
                    Msg::DeleteGroupResponse,
                    "Error trying to delete group",
                );
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::DeleteGroupResponse(response) => {
                self.common.cancel_task();
                response?;
                self.common
                    .props
                    .on_group_deleted
                    .emit(self.common.group.id);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for DeleteGroup {
    type Message = Msg;
    type Properties = DeleteGroupProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(props, link),
            node_ref: NodeRef::default(),
            modal: None,
        }
    }

    fn rendered(&mut self, first_render: bool) {
        if first_render {
            self.modal = Some(Modal::new(
                self.node_ref
                    .cast::<web_sys::Element>()
                    .expect("Modal node is not an element"),
            ));
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update_and_report_error(
            self,
            msg,
            self.common.on_error.clone(),
        )
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        html! {
          <>
          <button
            class="btn btn-danger"
            disabled=self.common.is_task_running()
            onclick=self.common.callback(|_| Msg::ClickedDeleteGroup)>
            <i class="bi-x-circle-fill" aria-label="Delete group" />
          </button>
          {self.show_modal()}
          </>
        }
    }
}

impl DeleteGroup {
    fn show_modal(&self) -> Html {
        html! {
          <div
            class="modal fade"
            id="deleteGroupModal".to_string() + &self.common.group.id.to_string()
            tabindex="-1"
            aria-labelledby="deleteGroupModalLabel"
            aria-hidden="true"
            ref=self.node_ref.clone()>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteGroupModalLabel">{"Delete group?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick=self.common.callback(|_| Msg::DismissModal) />
                </div>
                <div class="modal-body">
                <span>
                  {"Are you sure you want to delete group "}
                  <b>{&self.common.group.display_name}</b>{"?"}
                </span>
                </div>
                <div class="modal-footer">
                  <button
                    type="button"
                    class="btn btn-secondary"
                    onclick=self.common.callback(|_| Msg::DismissModal)>
                      <i class="bi-x-circle me-2"></i>
                      {"Cancel"}
                  </button>
                  <button
                    type="button"
                    onclick=self.common.callback(|_| Msg::ConfirmDeleteGroup)
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
