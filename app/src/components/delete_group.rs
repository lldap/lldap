use crate::{
    components::group_table::Group,
    infra::{api::HostService, modal::Modal},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;
use yew::services::fetch::FetchTask;
use yewtil::NeqAssign;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_group.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteGroupQuery;

pub struct DeleteGroup {
    link: ComponentLink<Self>,
    props: DeleteGroupProps,
    node_ref: NodeRef,
    modal: Option<Modal>,
    _task: Option<FetchTask>,
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

impl Component for DeleteGroup {
    type Message = Msg;
    type Properties = DeleteGroupProps;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            props,
            node_ref: NodeRef::default(),
            modal: None,
            _task: None,
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
        match msg {
            Msg::ClickedDeleteGroup => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmDeleteGroup => {
                self.update(Msg::DismissModal);
                self._task = HostService::graphql_query::<DeleteGroupQuery>(
                    delete_group_query::Variables {
                        group_id: self.props.group.id,
                    },
                    self.link.callback(Msg::DeleteGroupResponse),
                    "Error trying to delete group",
                )
                .map_err(|e| self.props.on_error.emit(e))
                .ok();
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::DeleteGroupResponse(response) => {
                if let Err(e) = response {
                    self.props.on_error.emit(e);
                } else {
                    self.props.on_group_deleted.emit(self.props.group.id);
                }
            }
        }
        true
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.props.neq_assign(props)
    }

    fn view(&self) -> Html {
        html! {
          <>
          <button
            class="btn btn-danger"
            onclick=self.link.callback(|_| Msg::ClickedDeleteGroup)>
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
            id="exampleModal".to_string() + &self.props.group.id.to_string()
            tabindex="-1"
            aria-labelledby="exampleModalLabel"
            aria-hidden="true"
            ref=self.node_ref.clone()>
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="exampleModalLabel">{"Delete group?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick=self.link.callback(|_| Msg::DismissModal) />
                </div>
                <div class="modal-body">
                <span>
                  {"Are you sure you want to delete group "}
                  <b>{&self.props.group.display_name}</b>{"?"}
                </span>
                </div>
                <div class="modal-footer">
                  <button
                    type="button"
                    class="btn btn-secondary"
                    onclick=self.link.callback(|_| Msg::DismissModal)>
                      {"Cancel"}
                  </button>
                  <button
                    type="button"
                    onclick=self.link.callback(|_| Msg::ConfirmDeleteGroup)
                    class="btn btn-danger">{"Yes, I'm sure"}</button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
