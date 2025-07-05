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
            html! {
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
                        <th>{"Login Enabled"}</th>
                        <th>{"Delete"}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.iter().map(|u| self.view_user(ctx, u)).collect::<Vec<_>>()}
                    </tbody>
                  </table>
                </div>
            }
        };
        match &self.users {
            None => html! {{"Loading..."}},
            Some(users) => make_table(users),
        }
    }

    fn view_user(&self, ctx: &Context<Self>, user: &User) -> Html {
        let link = &ctx.link();
        let status_class = if user.login_enabled {
            "text-success"
        } else {
            "text-danger"
        };
        let status_text = if user.login_enabled {
            "Enabled"
        } else {
            "Login Blocked"
        };
        html! {
          <tr key={user.id.clone()}>
              <td><Link to={AppRoute::UserDetails{user_id: user.id.clone()}}>{&user.id}</Link></td>
              <td>{&user.email}</td>
              <td>{&user.display_name}</td>
              <td>{&user.first_name}</td>
              <td>{&user.last_name}</td>
              <td>{&user.creation_date.naive_local().date()}</td>
              <td><span class={status_class}>{status_text}</span></td>
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
