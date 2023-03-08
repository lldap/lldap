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
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::SubmitRemoveGroup => self.submit_remove_group(ctx),
            Msg::RemoveGroupResponse(response) => {
                response?;
                ctx.props()
                    .on_user_removed_from_group
                    .emit((ctx.props().username.clone(), ctx.props().group_id));
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl RemoveUserFromGroupComponent {
    fn submit_remove_group(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<RemoveUserFromGroup, _>(
            ctx,
            remove_user_from_group::Variables {
                user: ctx.props().username.clone(),
                group: ctx.props().group_id,
            },
            Msg::RemoveGroupResponse,
            "Error trying to initiate removing the user from a group",
        );
    }
}

impl Component for RemoveUserFromGroupComponent {
    type Message = Msg;
    type Properties = Props;

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
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
          <button
            class="btn btn-danger"
            disabled={self.common.is_task_running()}
            onclick={link.callback(|_| Msg::SubmitRemoveGroup)}>
            <i class="bi-x-circle-fill" aria-label="Remove user from group" />
          </button>
        }
    }
}
