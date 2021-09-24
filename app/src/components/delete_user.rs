use crate::infra::{api::HostService, modal::Modal};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;
use yew::services::fetch::FetchTask;
use yewtil::NeqAssign;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteUserQuery;

pub struct DeleteUser {
    link: ComponentLink<Self>,
    props: DeleteUserProps,
    node_ref: NodeRef,
    modal: Option<Modal>,
    _task: Option<FetchTask>,
}

#[derive(yew::Properties, Clone, PartialEq, Debug)]
pub struct DeleteUserProps {
    pub username: String,
    pub on_user_deleted: Callback<String>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    ClickedDeleteUser,
    ConfirmDeleteUser,
    DismissModal,
    DeleteUserResponse(Result<delete_user_query::ResponseData>),
}

impl Component for DeleteUser {
    type Message = Msg;
    type Properties = DeleteUserProps;

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
            Msg::ClickedDeleteUser => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmDeleteUser => {
                self.update(Msg::DismissModal);
                self._task = HostService::graphql_query::<DeleteUserQuery>(
                    delete_user_query::Variables {
                        user: self.props.username.clone(),
                    },
                    self.link.callback(Msg::DeleteUserResponse),
                    "Error trying to delete user",
                )
                .map_err(|e| self.props.on_error.emit(e))
                .ok();
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::DeleteUserResponse(response) => {
                if let Err(e) = response {
                    self.props.on_error.emit(e);
                } else {
                    self.props.on_user_deleted.emit(self.props.username.clone());
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
            onclick=self.link.callback(|_| Msg::ClickedDeleteUser)>
            <i class="bi-x-circle-fill" aria-label="Delete user" />
          </button>
          {self.show_modal()}
          </>
        }
    }
}

impl DeleteUser {
    fn show_modal(&self) -> Html {
        html! {
          <div
            class="modal fade"
            id="exampleModal".to_string() + &self.props.username
            tabindex="-1"
            //role="dialog"
            aria-labelledby="exampleModalLabel"
            aria-hidden="true"
            ref=self.node_ref.clone()>
            <div class="modal-dialog" /*role="document"*/>
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="exampleModalLabel">{"Delete user?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick=self.link.callback(|_| Msg::DismissModal) />
                </div>
                <div class="modal-body">
                <span>
                  {"Are you sure you want to delete user "}
                  <b>{&self.props.username}</b>{"?"}
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
                    onclick=self.link.callback(|_| Msg::ConfirmDeleteUser)
                    class="btn btn-danger">{"Yes, I'm sure"}</button>
                </div>
              </div>
            </div>
          </div>
        }
    }
}
