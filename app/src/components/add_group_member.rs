use crate::{
    components::select::{Select, SelectOption, SelectOptionProps},
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use std::collections::HashSet;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/add_user_to_group.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct AddUserToGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_users.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq,Hash",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUserNames;
pub type User = list_user_names::ListUserNamesUsers;

pub struct AddGroupMemberComponent {
    common: CommonComponentParts<Self>,
    /// The list of existing users, initially not loaded.
    user_list: Option<Vec<User>>,
    /// The currently selected user.
    selected_user: Option<User>,
}

pub enum Msg {
    UserListResponse(Result<list_user_names::ResponseData>),
    SubmitAddMember,
    AddMemberResponse(Result<add_user_to_group::ResponseData>),
    SelectionChanged(Option<SelectOptionProps>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub group_id: i64,
    pub users: Vec<User>,
    pub on_user_added_to_group: Callback<User>,
    pub on_error: Callback<Error>,
}

impl CommonComponent<AddGroupMemberComponent> for AddGroupMemberComponent {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::UserListResponse(response) => {
                self.user_list = Some(response?.users);
            }
            Msg::SubmitAddMember => return self.submit_add_member(ctx),
            Msg::AddMemberResponse(response) => {
                response?;
                let user = self
                    .selected_user
                    .as_ref()
                    .expect("Could not get selected user")
                    .clone();
                // Remove the user from the dropdown.
                ctx.props().on_user_added_to_group.emit(user);
            }
            Msg::SelectionChanged(option_props) => {
                let was_some = self.selected_user.is_some();
                self.selected_user = option_props.map(|u| User {
                    id: u.value,
                    display_name: u.text,
                });
                return Ok(self.selected_user.is_some() != was_some);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl AddGroupMemberComponent {
    fn get_user_list(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<ListUserNames, _>(
            ctx,
            list_user_names::Variables { filters: None },
            Msg::UserListResponse,
            "Error trying to fetch user list",
        );
    }

    fn submit_add_member(&mut self, ctx: &Context<Self>) -> Result<bool> {
        let user_id = match self.selected_user.clone() {
            None => return Ok(false),
            Some(user) => user.id,
        };
        self.common.call_graphql::<AddUserToGroup, _>(
            ctx,
            add_user_to_group::Variables {
                user: user_id,
                group: ctx.props().group_id,
            },
            Msg::AddMemberResponse,
            "Error trying to initiate adding the user to a group",
        );
        Ok(true)
    }

    fn get_selectable_user_list(&self, ctx: &Context<Self>, user_list: &[User]) -> Vec<User> {
        let user_groups = ctx.props().users.iter().collect::<HashSet<_>>();
        user_list
            .iter()
            .filter(|u| !user_groups.contains(u))
            .map(Clone::clone)
            .collect()
    }
}

impl Component for AddGroupMemberComponent {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut res = Self {
            common: CommonComponentParts::<Self>::create(),
            user_list: None,
            selected_user: None,
        };
        res.get_user_list(ctx);
        res
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
        let link = ctx.link();
        if let Some(user_list) = &self.user_list {
            let to_add_user_list = self.get_selectable_user_list(ctx, user_list);
            #[allow(unused_braces)]
            let make_select_option = |user: User| {
                let name = if user.display_name.is_empty() {
                    user.id.clone()
                } else {
                    user.display_name.clone()
                };
                html_nested! {
                    <SelectOption value={user.id.clone()} text={name} key={user.id} />
                }
            };
            html! {
            <div class="row">
              <div class="col-sm-3">
                <Select on_selection_change={link.callback(Msg::SelectionChanged)}>
                  {
                    to_add_user_list
                        .into_iter()
                        .map(make_select_option)
                        .collect::<Vec<_>>()
                  }
                </Select>
              </div>
              <div class="col-3">
                <button
                  class="btn btn-secondary"
                  disabled={self.selected_user.is_none() || self.common.is_task_running()}
                  onclick={link.callback(|_| Msg::SubmitAddMember)}>
                   <i class="bi-person-plus me-2"></i>
                  {"Add to group"}
                </button>
              </div>
            </div>
            }
        } else {
            html! {
              {"Loading groups"}
            }
        }
    }
}
