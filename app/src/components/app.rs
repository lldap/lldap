use crate::{
    components::{
        change_password::ChangePasswordForm,
        create_user::CreateUserForm,
        login::LoginForm,
        logout::LogoutButton,
        router::{AppRoute, NavButton},
        user_details::UserDetails,
        user_table::UserTable,
    },
    infra::cookies::get_cookie,
};
use yew::prelude::*;
use yew::services::ConsoleService;
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
    router::Router,
    service::RouteService,
};

pub struct App {
    link: ComponentLink<Self>,
    user_info: Option<(String, bool)>,
    redirect_to: Option<AppRoute>,
    route_dispatcher: RouteAgentDispatcher,
}

pub enum Msg {
    Login((String, bool)),
    Logout,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut app = Self {
            link,
            user_info: get_cookie("user_id")
                .unwrap_or_else(|e| {
                    ConsoleService::error(&e.to_string());
                    None
                })
                .and_then(|u| {
                    get_cookie("is_admin")
                        .map(|so| so.map(|s| (u, s == "true")))
                        .unwrap_or_else(|e| {
                            ConsoleService::error(&e.to_string());
                            None
                        })
                }),
            redirect_to: Self::get_redirect_route(),
            route_dispatcher: RouteAgentDispatcher::new(),
        };
        app.apply_initial_redirections();
        app
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Login((user_name, is_admin)) => {
                self.user_info = Some((user_name.clone(), is_admin));
                self.route_dispatcher
                    .send(RouteRequest::ChangeRoute(Route::from(
                        self.redirect_to.take().unwrap_or_else(|| {
                            if is_admin {
                                AppRoute::ListUsers
                            } else {
                                AppRoute::UserDetails(user_name.clone())
                            }
                        }),
                    )));
            }
            Msg::Logout => {
                self.user_info = None;
                self.redirect_to = None;
            }
        }
        if self.user_info.is_none() {
            self.route_dispatcher
                .send(RouteRequest::ReplaceRoute(Route::new_no_state("/login")));
        }
        true
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        let link = self.link.clone();
        let is_admin = self.is_admin();
        html! {
            <div>
                <h1>{ "LLDAP" }</h1>
                <Router<AppRoute>
                  render = Router::render(move |switch: AppRoute| {
                      match switch {
                          AppRoute::Login => html! {
                              <LoginForm on_logged_in=link.callback(Msg::Login)/>
                          },
                          AppRoute::CreateUser => html! {
                              <div>
                                <LogoutButton on_logged_out=link.callback(|_| Msg::Logout) />
                                <CreateUserForm/>
                              </div>
                          },
                          AppRoute::Index | AppRoute::ListUsers => html! {
                              <div>
                                <LogoutButton on_logged_out=link.callback(|_| Msg::Logout) />
                                <UserTable />
                                <NavButton route=AppRoute::CreateUser>{"Create a user"}</NavButton>
                              </div>
                          },
                          AppRoute::UserDetails(username) => html! {
                              <div>
                                <LogoutButton on_logged_out=link.callback(|_| Msg::Logout) />
                                <UserDetails username=username.clone() is_admin=is_admin />
                              </div>
                          },
                          AppRoute::ChangePassword(username) => html! {
                              <div>
                                <LogoutButton on_logged_out=link.callback(|_| Msg::Logout) />
                                <ChangePasswordForm username=username.clone() is_admin=is_admin />
                              </div>
                          }
                      }
                  })
                />
            </div>
        }
    }
}

impl App {
    fn get_redirect_route() -> Option<AppRoute> {
        let route_service = RouteService::<()>::new();
        let current_route = route_service.get_path();
        if current_route.is_empty() || current_route == "/" || current_route.contains("login") {
            None
        } else {
            use yew_router::Switch;
            AppRoute::from_route_part::<()>(current_route, None).0
        }
    }

    fn apply_initial_redirections(&mut self) {
        match &self.user_info {
            None => {
                self.route_dispatcher
                    .send(RouteRequest::ReplaceRoute(Route::new_no_state("/login")));
            }
            Some((user_name, is_admin)) => match &self.redirect_to {
                Some(url) => {
                    self.route_dispatcher
                        .send(RouteRequest::ReplaceRoute(Route::from(url.clone())));
                }
                None => {
                    if *is_admin {
                        self.route_dispatcher
                            .send(RouteRequest::ReplaceRoute(Route::new_no_state("/users")));
                    } else {
                        self.route_dispatcher
                            .send(RouteRequest::ReplaceRoute(Route::from(
                                AppRoute::UserDetails(user_name.clone()),
                            )));
                    }
                }
            },
        }
    }

    fn is_admin(&self) -> bool {
        match &self.user_info {
            None => false,
            Some((_, is_admin)) => *is_admin,
        }
    }
}
