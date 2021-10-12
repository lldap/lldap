use crate::infra::api::HostService;
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};

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
    link: ComponentLink<Self>,
    props: Props,
    // Used to keep the request alive long enough.
    task: Option<FetchTask>,
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

impl RemoveUserFromGroupComponent {
    fn submit_remove_group(&mut self) -> Result<bool> {
        let group = self.props.group_id;
        self.task = HostService::graphql_query::<RemoveUserFromGroup>(
            remove_user_from_group::Variables {
                user: self.props.username.clone(),
                group,
            },
            self.link.callback(Msg::RemoveGroupResponse),
            "Error trying to initiate removing the user from a group",
        )
        .map_err(|e| {
            ConsoleService::log(&e.to_string());
            e
        })
        .ok();
        Ok(true)
    }

    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::SubmitRemoveGroup => return self.submit_remove_group(),
            Msg::RemoveGroupResponse(response) => {
                response?;
                self.task = None;
                self.props
                    .on_user_removed_from_group
                    .emit((self.props.username.clone(), self.props.group_id));
            }
        }
        Ok(true)
    }
}

impl Component for RemoveUserFromGroupComponent {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            props,
            task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match self.handle_msg(msg) {
            Err(e) => {
                self.task = None;
                self.props.on_error.emit(e);
                true
            }
            Ok(b) => b,
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
          <button
            class="btn btn-danger"
            disabled=self.task.is_some()
            onclick=self.link.callback(|_| Msg::SubmitRemoveGroup)>
            <i class="bi-x-circle-fill" aria-label="Remove user from group" />
          </button>
        }
    }
}
