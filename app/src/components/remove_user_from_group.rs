use crate::infra::common_component::{CommonComponent, CommonComponentParts};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/remove_user_from_group.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct RemoveUserFromGroup;

pub struct RemoveUserFromGroupComponent {
    common: CommonComponentParts<Self>,
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub username: String,
    pub group_id: i64,
    pub on_user_removed_from_group: Callback<(String, i64)>,
    pub on_error: Callback<Error>,
}

pub enum Msg {
    SubmitRemoveGroup,
    RemoveGroupResponse(Result<remove_user_from_group::ResponseData>),
}

impl CommonComponent<RemoveUserFromGroupComponent> for RemoveUserFromGroupComponent {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::SubmitRemoveGroup => self.submit_remove_group(),
            Msg::RemoveGroupResponse(response) => {
                response?;
                self.common.cancel_task();
                self.common.props.on_user_removed_from_group.emit((
                    self.common.props.username.clone(),
                    self.common.props.group_id,
                ));
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl RemoveUserFromGroupComponent {
    fn submit_remove_group(&mut self) {
        self.common.call_graphql::<RemoveUserFromGroup, _>(
            remove_user_from_group::Variables {
                user: self.common.props.username.clone(),
                group: self.common.props.group_id,
            },
            Msg::RemoveGroupResponse,
            "Error trying to initiate removing the user from a group",
        );
    }
}

impl Component for RemoveUserFromGroupComponent {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(props, link),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update_and_report_error(
            self,
            msg,
            self.common.props.on_error.clone(),
        )
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
          <button
            class="btn btn-danger"
            disabled=self.common.is_task_running()
            onclick=self.common.callback(|_| Msg::SubmitRemoveGroup)>
            <i class="bi-x-circle-fill" aria-label="Remove user from group" />
          </button>
        }
    }
}
