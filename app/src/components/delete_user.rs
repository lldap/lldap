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
    query_path = "queries/delete_user.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeleteUserQuery;

pub struct DeleteUser {
    common: CommonComponentParts<Self>,
    node_ref: NodeRef,
    modal: Option<Modal>,
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

impl CommonComponent<DeleteUser> for DeleteUser {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ClickedDeleteUser => {
                self.modal.as_ref().expect("modal not initialized").show();
            }
            Msg::ConfirmDeleteUser => {
                self.update(Msg::DismissModal);
                self.common.call_graphql::<DeleteUserQuery, _>(
                    delete_user_query::Variables {
                        user: self.common.username.clone(),
                    },
                    Msg::DeleteUserResponse,
                    "Error trying to delete user",
                );
            }
            Msg::DismissModal => {
                self.modal.as_ref().expect("modal not initialized").hide();
            }
            Msg::DeleteUserResponse(response) => {
                self.common.cancel_task();
                response?;
                self.common
                    .props
                    .on_user_deleted
                    .emit(self.common.username.clone());
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for DeleteUser {
    type Message = Msg;
    type Properties = DeleteUserProps;

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
        let link = &self.common;
        html! {
          <>
          <button
            class="btn btn-danger"
            disabled={self.common.is_task_running()}
            onclick={link.callback(|_| Msg::ClickedDeleteUser)}>
            <i class="bi-x-circle-fill" aria-label="Delete user" />
          </button>
          {self.show_modal()}
          </>
        }
    }
}

impl DeleteUser {
    fn show_modal(&self) -> Html {
        let link = &self.common;
        html! {
          <div
            class="modal fade"
            id={"deleteUserModal".to_string() + &self.common.username}
            tabindex="-1"
            //role="dialog"
            aria-labelledby="deleteUserModalLabel"
            aria-hidden="true"
            ref={self.node_ref.clone()}>
            <div class="modal-dialog" /*role="document"*/>
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteUserModalLabel">{"Delete user?"}</h5>
                  <button
                    type="button"
                    class="btn-close"
                    aria-label="Close"
                    onclick={link.callback(|_| Msg::DismissModal)} />
                </div>
                <div class="modal-body">
                <span>
                  {"Are you sure you want to delete user "}
                  <b>{&self.common.username}</b>{"?"}
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
                    onclick={link.callback(|_| Msg::ConfirmDeleteUser)}
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
