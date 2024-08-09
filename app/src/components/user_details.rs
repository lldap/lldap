use crate::{
    components::{
        add_user_to_group::AddUserToGroupComponent,
        remove_user_from_group::RemoveUserFromGroupComponent,
        router::{AppRoute, Link},
        user_details_form::UserDetailsForm,
    },
    convert_attribute_type,
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_details.graphql",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserDetails;

pub type User = get_user_details::GetUserDetailsUser;
pub type Group = get_user_details::GetUserDetailsUserGroups;
pub type Attribute = get_user_details::GetUserDetailsUserAttributes;
pub type AttributeSchema = get_user_details::GetUserDetailsSchemaUserSchemaAttributes;
pub type AttributeType = get_user_details::AttributeType;

convert_attribute_type!(AttributeType);

pub struct UserDetails {
    common: CommonComponentParts<Self>,
    /// The user info. If none, the error is in `error`. If `error` is None, then we haven't
    /// received the server response yet.
    user_and_schema: Option<(User, Vec<AttributeSchema>)>,
}

impl UserDetails {
    fn user(&self) -> Option<&User> {
        self.user_and_schema.as_ref().map(|t| &t.0)
    }
    fn schema(&self) -> Option<&Vec<AttributeSchema>> {
        self.user_and_schema.as_ref().map(|t| &t.1)
    }
    fn mut_groups(&mut self) -> &mut Vec<Group> {
        &mut self.user_and_schema.as_mut().unwrap().0.groups
    }
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the user details response, either the user data or an error.
    UserDetailsResponse(Result<get_user_details::ResponseData>),
    OnError(Error),
    OnUserAddedToGroup(Group),
    OnUserRemovedFromGroup((String, i64)),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
}

impl CommonComponent<UserDetails> for UserDetails {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::UserDetailsResponse(response) => match response {
                Ok(user) => {
                    self.user_and_schema = Some((user.user, user.schema.user_schema.attributes))
                }
                Err(e) => {
                    self.user_and_schema = None;
                    bail!("Error getting user details: {}", e);
                }
            },
            Msg::OnError(e) => return Err(e),
            Msg::OnUserAddedToGroup(group) => {
                self.mut_groups().push(group);
            }
            Msg::OnUserRemovedFromGroup((_, group_id)) => {
                self.mut_groups().retain(|g| g.id != group_id);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl UserDetails {
    fn get_user_details(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetUserDetails, _>(
            ctx,
            get_user_details::Variables {
                id: ctx.props().username.clone(),
            },
            Msg::UserDetailsResponse,
            "Error trying to fetch user details",
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

    fn view_group_memberships(&self, ctx: &Context<Self>, u: &User) -> Html {
        let link = &ctx.link();
        let make_group_row = |group: &Group| {
            let display_name = group.display_name.clone();
            html! {
              <tr key={"groupRow_".to_string() + &display_name}>
                {if ctx.props().is_admin { html! {
                  <>
                    <td>
                      <Link to={AppRoute::GroupDetails{group_id: group.id}}>
                        {&group.display_name}
                      </Link>
                    </td>
                    <td>
                      <RemoveUserFromGroupComponent
                        username={u.id.clone()}
                        group_id={group.id}
                        on_user_removed_from_group={link.callback(Msg::OnUserRemovedFromGroup)}
                        on_error={link.callback(Msg::OnError)}/>
                    </td>
                  </>
                } } else { html! {
                  <td>{&group.display_name}</td>
                } } }
              </tr>
            }
        };
        html! {
          <>
            <h5 class="row m-3 fw-bold">{"Group memberships"}</h5>
            <div class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr key="headerRow">
                    <th>{"Group"}</th>
                    { if ctx.props().is_admin { html!{ <th></th> }} else { html!{} }}
                  </tr>
                </thead>
                <tbody>
                  {if u.groups.is_empty() {
                    html! {
                      <tr key="EmptyRow">
                        <td>{"This user is not a member of any groups."}</td>
                      </tr>
                    }
                  } else {
                    html! {<>{u.groups.iter().map(make_group_row).collect::<Vec<_>>()}</>}
                  }}
                </tbody>
              </table>
            </div>
          </>
        }
    }

    fn view_add_group_button(&self, ctx: &Context<Self>, u: &User) -> Html {
        let link = &ctx.link();
        if ctx.props().is_admin {
            html! {
                <AddUserToGroupComponent
                    username={u.id.clone()}
                    groups={u.groups.clone()}
                    on_error={link.callback(Msg::OnError)}
                    on_user_added_to_group={link.callback(Msg::OnUserAddedToGroup)}/>
            }
        } else {
            html! {}
        }
    }
}

impl Component for UserDetails {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = Self {
            common: CommonComponentParts::<Self>::create(),
            user_and_schema: None,
        };
        table.get_user_details(ctx);
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match (&self.user_and_schema, &self.common.error) {
            (Some((u, schema)), error) => {
                html! {
                  <>
                    <h3>{u.id.to_string()}</h3>
                    <div class="d-flex flex-row-reverse">
                      <Link
                        to={AppRoute::ChangePassword{user_id: u.id.clone()}}
                        classes="btn btn-secondary">
                        <i class="bi-key me-2"></i>
                        {"Modify password"}
                      </Link>
                    </div>
                    <div>
                      <h5 class="row m-3 fw-bold">{"User details"}</h5>
                    </div>
                    <UserDetailsForm user={u.clone()} user_attributes_schema={schema.clone()} />
                    {self.view_group_memberships(ctx, u)}
                    {self.view_add_group_button(ctx, u)}
                    {self.view_messages(error)}
                  </>
                }
            }
            (None, None) => html! {{"Loading..."}},
            (None, Some(e)) => html! {<div>{"Error: "}{e.to_string()}</div>},
        }
    }
}
