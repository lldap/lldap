use crate::{
    components::{
        select::{Select, SelectOption, SelectOptionProps},
        user_details::Group,
    },
    infra::api::HostService,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use std::collections::HashSet;
use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};
use yewtil::NeqAssign;

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
    query_path = "queries/get_group_list.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupList;
type GroupListGroup = get_group_list::GetGroupListGroups;

impl From<GroupListGroup> for Group {
    fn from(group: GroupListGroup) -> Self {
        Self {
            id: group.id,
            display_name: group.display_name,
        }
    }
}

pub struct AddUserToGroupComponent {
    link: ComponentLink<Self>,
    props: Props,
    /// The list of existing groups, initially not loaded.
    group_list: Option<Vec<Group>>,
    /// The currently selected group.
    selected_group: Option<Group>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    GroupListResponse(Result<get_group_list::ResponseData>),
    SubmitAddGroup,
    AddGroupResponse(Result<add_user_to_group::ResponseData>),
    SelectionChanged(Option<SelectOptionProps>),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub username: String,
    pub groups: Vec<Group>,
    pub on_user_added_to_group: Callback<Group>,
    pub on_error: Callback<Error>,
}

impl AddUserToGroupComponent {
    fn get_group_list(&mut self) {
        self._task = HostService::graphql_query::<GetGroupList>(
            get_group_list::Variables,
            self.link.callback(Msg::GroupListResponse),
            "Error trying to fetch group list",
        )
        .map_err(|e| {
            ConsoleService::log(&e.to_string());
            e
        })
        .ok();
    }

    fn submit_add_group(&mut self) -> Result<bool> {
        let group_id = match &self.selected_group {
            None => return Ok(false),
            Some(group) => group.id,
        };
        self._task = HostService::graphql_query::<AddUserToGroup>(
            add_user_to_group::Variables {
                user: self.props.username.clone(),
                group: group_id,
            },
            self.link.callback(Msg::AddGroupResponse),
            "Error trying to initiate adding the user to a group",
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
            Msg::GroupListResponse(response) => {
                self.group_list = Some(response?.groups.into_iter().map(Into::into).collect());
            }
            Msg::SubmitAddGroup => return self.submit_add_group(),
            Msg::AddGroupResponse(response) => {
                response?;
                // Adding the user to the group succeeded, we're not in the process of adding a
                // group anymore.
                let group = self
                    .selected_group
                    .as_ref()
                    .expect("Could not get selected group")
                    .clone();
                // Remove the group from the dropdown.
                self.props.on_user_added_to_group.emit(group);
            }
            Msg::SelectionChanged(option_props) => {
                self.selected_group = option_props.map(|props| Group {
                    id: props.value.parse::<i64>().unwrap(),
                    display_name: props.text,
                });
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn get_selectable_group_list(&self, group_list: &[Group]) -> Vec<Group> {
        let user_groups = self.props.groups.iter().collect::<HashSet<_>>();
        group_list
            .iter()
            .filter(|g| !user_groups.contains(g))
            .map(Clone::clone)
            .collect()
    }
}

impl Component for AddUserToGroupComponent {
    type Message = Msg;
    type Properties = Props;
    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut res = Self {
            link,
            props,
            group_list: None,
            selected_group: None,
            _task: None,
        };
        res.get_group_list();
        res
    }
    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match self.handle_msg(msg) {
            Err(e) => {
                ConsoleService::error(&e.to_string());
                self.props.on_error.emit(e);
                true
            }
            Ok(b) => b,
        }
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.props.neq_assign(props)
    }

    fn view(&self) -> Html {
        if let Some(group_list) = &self.group_list {
            let to_add_group_list = self.get_selectable_group_list(group_list);
            #[allow(unused_braces)]
            let make_select_option = |group: Group| {
                html_nested! {
                    <SelectOption value=group.id.to_string() text=group.display_name key=group.id />
                }
            };
            html! {
            <>
              <td>
                <Select on_selection_change=self.link.callback(Msg::SelectionChanged)>
                  {
                    to_add_group_list
                        .into_iter()
                        .map(make_select_option)
                        .collect::<Vec<_>>()
                  }
                </Select>
              </td>
                  <td>
                    <button onclick=self.link.callback(
                        |_| Msg::SubmitAddGroup)>
                      {"Add"}
                    </button>
                  </td>
            </>
            }
        } else {
            html! {
              <>
                <td>{"Loading groups"}</td>
                <td></td>
              </>
            }
        }
    }
}
