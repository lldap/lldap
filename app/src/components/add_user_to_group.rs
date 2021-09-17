use crate::{
    components::user_details::{Group, User},
    infra::api::HostService,
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use std::collections::HashSet;
use yew::{
    html::ChangeData,
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};

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
    user: User,
    /// The list of existing groups, initially not loaded.
    group_list: Option<Vec<Group>>,
    /// Whether the "+" button has been clicked.
    add_group: bool,
    on_error: Callback<Error>,
    on_user_added_to_group: Callback<Group>,
    selected_group: Option<Group>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

pub enum Msg {
    AddGroupButtonClicked,
    GroupListResponse(Result<get_group_list::ResponseData>),
    SubmitAddGroup,
    AddGroupResponse(Result<add_user_to_group::ResponseData>),
    SelectionChanged(ChangeData),
}

#[derive(yew::Properties, Clone, PartialEq)]
pub struct Props {
    pub user: User,
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
                user: self.user.id.clone(),
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
            Msg::AddGroupButtonClicked => {
                if self.group_list.is_none() {
                    self.get_group_list();
                } else {
                    self.set_default_selection();
                }
                self.add_group = true;
            }
            Msg::GroupListResponse(response) => {
                self.group_list = Some(response?.groups.into_iter().map(Into::into).collect());
                self.set_default_selection();
            }
            Msg::SubmitAddGroup => return self.submit_add_group(),
            Msg::AddGroupResponse(response) => {
                response?;
                // Adding the user to the group succeeded, we're not in the process of adding a
                // group anymore.
                self.add_group = false;
                let group = self
                    .selected_group
                    .as_ref()
                    .expect("Could not get selected group")
                    .clone();
                // Remove the group from the dropdown.
                self.on_user_added_to_group.emit(group);
            }
            Msg::SelectionChanged(data) => match data {
                ChangeData::Select(e) => {
                    self.update_selection(e);
                }
                _ => unreachable!(),
            },
        }
        Ok(true)
    }

    fn update_selection(&mut self, e: web_sys::HtmlSelectElement) {
        if e.selected_index() == -1 {
            self.selected_group = None;
        } else {
            use wasm_bindgen::JsCast;
            let option = e
                .options()
                .get_with_index(e.selected_index() as u32)
                .unwrap()
                .dyn_into::<web_sys::HtmlOptionElement>()
                .unwrap();
            self.selected_group = Some(Group {
                id: option.value().parse::<i64>().unwrap(),
                display_name: option.text(),
            });
        }
    }

    fn get_selectable_group_list(&self, group_list: &Vec<Group>) -> Vec<Group> {
        let user_groups = self.user.groups.iter().collect::<HashSet<_>>();
        group_list
            .iter()
            .filter(|g| !user_groups.contains(g))
            .map(Clone::clone)
            .collect()
    }

    fn set_default_selection(&mut self) {
        self.selected_group = (|| {
            let groups = self.get_selectable_group_list(self.group_list.as_ref()?);
            groups.into_iter().next()
        })();
    }
}

impl Component for AddUserToGroupComponent {
    type Message = Msg;
    type Properties = Props;
    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            user: props.user,
            group_list: None,
            add_group: false,
            on_error: props.on_error,
            on_user_added_to_group: props.on_user_added_to_group,
            selected_group: None,
            _task: None,
        }
    }
    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match self.handle_msg(msg) {
            Err(e) => {
                ConsoleService::error(&e.to_string());
                self.on_error.emit(e);
                true
            }
            Ok(b) => b,
        }
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        if props.user.groups != self.user.groups {
            self.user = props.user;
            if self.selected_group.is_none() {
                self.set_default_selection();
            }
            true
        } else {
            false
        }
    }

    fn view(&self) -> Html {
        if !self.add_group {
            return html! {
            <>
              <td></td>
              <td>
                <button onclick=self.link.callback(
                    |_| Msg::AddGroupButtonClicked)>
                  {"+"}
                </button>
              </td>
            </>
            };
        }

        if let Some(group_list) = &self.group_list {
            let to_add_group_list = self.get_selectable_group_list(&group_list);
            let make_select_option = |group: Group| {
                html! {
                    <option value={group.id.to_string()}>{group.display_name}</option>
                }
            };
            html! {
            <>
              <td>
                <select name="groupToAdd" id="groupToAdd"
                  onchange=self.link.callback(|e| Msg::SelectionChanged(e))>
                  {
                    to_add_group_list
                        .into_iter()
                        .map(make_select_option)
                        .collect::<Vec<_>>()
                  }
                </select>
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
