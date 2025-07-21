use crate::{
    components::{
        add_group_member::{self, AddGroupMemberComponent},
        group_details_form::GroupDetailsForm,
        remove_user_from_group::RemoveUserFromGroupComponent,
        router::{AppRoute, Link},
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::GraphQlAttributeSchema,
        schema::AttributeType,
    },
};
use anyhow::{Error, Result, bail};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_details.graphql",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("AttributeType")
)]
pub struct GetGroupDetails;

pub type Group = get_group_details::GetGroupDetailsGroup;
pub type User = get_group_details::GetGroupDetailsGroupUsers;
pub type AddGroupMemberUser = add_group_member::User;
pub type Attribute = get_group_details::GetGroupDetailsGroupAttributes;
pub type AttributeSchema = get_group_details::GetGroupDetailsSchemaGroupSchemaAttributes;

impl From<&AttributeSchema> for GraphQlAttributeSchema {
    fn from(attr: &AttributeSchema) -> Self {
        Self {
            name: attr.name.clone(),
            is_list: attr.is_list,
            is_readonly: attr.is_readonly,
            is_editable: attr.is_editable,
        }
    }
}

pub struct GroupDetails {
    common: CommonComponentParts<Self>,
    /// The group info. If none, the error is in `error`. If `error` is None, then we haven't
    /// received the server response yet.
    group_and_schema: Option<(Group, Vec<AttributeSchema>)>,
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the group details response, either the group data or an error.
    GroupDetailsResponse(Result<get_group_details::ResponseData>),
    OnError(Error),
    OnUserAddedToGroup(AddGroupMemberUser),
    OnUserRemovedFromGroup((String, i64)),
    DisplayNameUpdated,
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub group_id: i64,
    pub is_admin: bool,
}

impl GroupDetails {
    fn get_group_details(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetGroupDetails, _>(
            ctx,
            get_group_details::Variables {
                id: ctx.props().group_id,
            },
            Msg::GroupDetailsResponse,
            "Error trying to fetch group details",
        );
    }

    fn view_messages(&self, error: &Option<Error>) -> Html {
        if let Some(e) = error {
            html! {
              <div class="alert alert-danger">
                <span>{"Error: "}{e.to_string()}</span>
              </div>
            }
        } else {
            html! {}
        }
    }

    fn view_details(&self, ctx: &Context<Self>, g: &Group, schema: Vec<AttributeSchema>) -> Html {
        html! {
          <>
            <h3>{g.display_name.to_string()}</h3>
            <GroupDetailsForm
              group={g.clone()}
              group_attributes_schema={schema}
              is_admin={ctx.props().is_admin}
              on_display_name_updated={ctx.link().callback(|_| Msg::DisplayNameUpdated)}
            />
          </>
        }
    }

    fn view_user_list(&self, ctx: &Context<Self>, g: &Group) -> Html {
        let link = ctx.link();
        let make_user_row = |user: &User| {
            let user_id = user.id.clone();
            let display_name = user.display_name.clone();
            html! {
              <tr>
                <td>
                  <Link to={AppRoute::UserDetails{user_id: user_id.clone()}}>
                    {user_id.clone()}
                  </Link>
                </td>
                <td>{display_name}</td>
                <td>
                  <RemoveUserFromGroupComponent
                    username={user_id}
                    group_id={g.id}
                    on_user_removed_from_group={link.callback(Msg::OnUserRemovedFromGroup)}
                    on_error={link.callback(Msg::OnError)}/>
                </td>
              </tr>
            }
        };
        html! {
          <>
            <h5 class="fw-bold">{"Members"}</h5>
            <div class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr key="headerRow">
                    <th>{"User Id"}</th>
                    <th>{"Display name"}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {if g.users.is_empty() {
                    html! {
                      <tr key="EmptyRow">
                        <td>{"There are no users in this group."}</td>
                        <td/>
                      </tr>
                    }
                  } else {
                    html! {<>{g.users.iter().map(make_user_row).collect::<Vec<_>>()}</>}
                  }}
                </tbody>
              </table>
            </div>
          </>
        }
    }

    fn view_add_user_button(&self, ctx: &Context<Self>, g: &Group) -> Html {
        let link = ctx.link();
        let users: Vec<_> = g
            .users
            .iter()
            .map(|u| AddGroupMemberUser {
                id: u.id.clone(),
                display_name: u.display_name.clone(),
            })
            .collect();
        html! {
            <AddGroupMemberComponent
                group_id={g.id}
                users={users}
                on_error={link.callback(Msg::OnError)}
                on_user_added_to_group={link.callback(Msg::OnUserAddedToGroup)}/>
        }
    }
}

impl CommonComponent<GroupDetails> for GroupDetails {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::GroupDetailsResponse(response) => match response {
                Ok(group) => {
                    self.group_and_schema =
                        Some((group.group, group.schema.group_schema.attributes))
                }
                Err(e) => {
                    self.group_and_schema = None;
                    bail!("Error getting user details: {}", e);
                }
            },
            Msg::OnError(e) => return Err(e),
            Msg::OnUserAddedToGroup(user) => {
                self.group_and_schema.as_mut().unwrap().0.users.push(User {
                    id: user.id,
                    display_name: user.display_name,
                });
            }
            Msg::OnUserRemovedFromGroup((user_id, _)) => {
                self.group_and_schema
                    .as_mut()
                    .unwrap()
                    .0
                    .users
                    .retain(|u| u.id != user_id);
            }
            Msg::DisplayNameUpdated => self.get_group_details(ctx),
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for GroupDetails {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = Self {
            common: CommonComponentParts::<Self>::create(),
            group_and_schema: None,
        };
        table.get_group_details(ctx);
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match (&self.group_and_schema, &self.common.error) {
            (None, None) => html! {{"Loading..."}},
            (None, Some(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
            (Some((group, schema)), error) => {
                html! {
                    <div>
                      {self.view_details(ctx, group, schema.clone())}
                      {self.view_user_list(ctx, group)}
                      {self.view_add_user_button(ctx, group)}
                      {self.view_messages(error)}
                    </div>
                }
            }
        }
    }
}
