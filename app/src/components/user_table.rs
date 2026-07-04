use crate::{
    components::{
        delete_user::DeleteUser,
        router::{AppRoute, Link},
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_users.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUsersQuery;

use list_users_query::{RequestFilter, ResponseData};

type User = list_users_query::ListUsersQueryUsers;

pub struct UserTable {
    common: CommonComponentParts<Self>,
    users: Option<Vec<User>>,
}

pub enum Msg {
    ListUsersResponse(Result<ResponseData>),
    OnUserDeleted(String),
    OnError(Error),
}

impl CommonComponent<UserTable> for UserTable {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::ListUsersResponse(users) => {
                self.users = Some(users?.users.into_iter().collect());
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::OnUserDeleted(user_id) => {
                debug_assert!(self.users.is_some());
                self.users.as_mut().unwrap().retain(|u| u.id != user_id);
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl UserTable {
    fn get_users(&mut self, ctx: &Context<Self>, req: Option<RequestFilter>) {
        self.common.call_graphql::<ListUsersQuery, _>(
            ctx,
            list_users_query::Variables { filters: req },
            Msg::ListUsersResponse,
            "Error trying to fetch users",
        );
    }
}

impl Component for UserTable {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = UserTable {
            common: CommonComponentParts::<Self>::create(),
            users: None,
        };
        table.get_users(ctx, None);
        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div>
              {self.view_users(ctx)}
              {self.view_errors()}
            </div>
        }
    }
}

impl UserTable {
    fn view_users(&self, ctx: &Context<Self>) -> Html {
        let make_table = |users: &Vec<User>| {
            // Answers "how many are left?" at a glance for admins with many
            // users; the count reaches zero as users log in, at which point
            // it is safe to upgrade to a version without legacy-password
            // support. Non-admins never receive the field, so they never see
            // the banner.
            let legacy_count = users
                .iter()
                .filter(|u| u.has_legacy_password == Some(true))
                .count();
            html! {
              <>
                {
                  if legacy_count > 0 {
                    html! {
                      <div class="alert alert-info" role="alert">
                        {format!(
                          "{} user{} still ha{} a pre-upgrade password. No action needed: passwords are upgraded automatically on each user's next login.",
                          legacy_count,
                          if legacy_count == 1 { "" } else { "s" },
                          if legacy_count == 1 { "s" } else { "ve" },
                        )}
                      </div>
                    }
                  } else {
                    html! {}
                  }
                }
                <div class="table-responsive">
                  <table class="table table-hover">
                    <thead>
                      <tr>
                        <th>{"User ID"}</th>
                        <th>{"Email"}</th>
                        <th>{"Display name"}</th>
                        <th>{"First name"}</th>
                        <th>{"Last name"}</th>
                        <th>{"Creation date"}</th>
                        <th>{"Delete"}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.iter().map(|u| self.view_user(ctx, u)).collect::<Vec<_>>()}
                    </tbody>
                  </table>
                </div>
              </>
            }
        };
        match &self.users {
            None => html! {{"Loading..."}},
            Some(users) => make_table(users),
        }
    }

    fn view_user(&self, ctx: &Context<Self>, user: &User) -> Html {
        let link = &ctx.link();
        html! {
          <tr key={user.id.clone()}>
              <td>
                <Link to={AppRoute::UserDetails{user_id: user.id.clone()}}>{&user.id}</Link>
                {
                  // Only admins receive this field (null otherwise). A user
                  // still on a legacy (opaque-ke 0.7) password hasn't logged
                  // in since the OPAQUE upgrade; the badge disappears once
                  // they do. The wording deliberately signals "no action
                  // needed" so admins aren't tempted to reset passwords.
                  if user.has_legacy_password == Some(true) {
                    html! {
                      <span
                        class="badge bg-warning text-dark ms-2 text-nowrap"
                        title="This user's password is in the pre-upgrade (opaque-ke 0.7) format. No action needed: it is upgraded automatically on their next login.">
                        {"Password upgrade pending"}
                      </span>
                    }
                  } else {
                    html! {}
                  }
                }
              </td>
              <td>{&user.email}</td>
              <td>{&user.display_name}</td>
              <td>{&user.first_name}</td>
              <td>{&user.last_name}</td>
              <td>{&user.creation_date.naive_local().date()}</td>
              <td>
                <DeleteUser
                  username={user.id.clone()}
                  on_user_deleted={link.callback(Msg::OnUserDeleted)}
                  on_error={link.callback(Msg::OnError)}/>
              </td>
          </tr>
        }
    }

    fn view_errors(&self) -> Html {
        match &self.common.error {
            None => html! {},
            Some(e) => html! {<div>{"Error: "}{e.to_string()}</div>},
        }
    }
}
