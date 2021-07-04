use crate::{
    cookies::get_cookie, create_user::CreateUserForm, login::LoginForm, logout::LogoutButton,
    user_table::UserTable,
};
use yew::prelude::*;
use yew::services::ConsoleService;
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    components::RouterAnchor,
    route::Route,
    router::Router,
    service::RouteService,
    Switch,
};

pub struct App {
    link: ComponentLink<Self>,
    user_info: Option<(String, bool)>,
    redirect_to: Option<String>,
    route_dispatcher: RouteAgentDispatcher,
}

pub enum Msg {
    Login((String, bool)),
    Logout,
}

#[derive(Switch, Debug, Clone)]
pub enum AppRoute {
    #[to = "/login"]
    Login,
    #[to = "/users"]
    ListUsers,
    #[to = "/create_user"]
    CreateUser,
    #[to = "/details/{user_id}"]
    UserDetails(String),
    #[to = "/"]
    Index,
}

type Link = RouterAnchor<AppRoute>;

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
                let user_route = "/details/".to_string() + &user_name;
                self.route_dispatcher
                    .send(RouteRequest::ChangeRoute(Route::new_no_state(
                        self.redirect_to.as_deref().unwrap_or_else(|| {
                            if is_admin {
                                "/users"
                            } else {
                                &user_route
                            }
                        }),
                    )));
            }
            Msg::Logout => {
                self.user_info = None;
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
                                <Link route=AppRoute::CreateUser>{"Create a user"}</Link>
                              </div>
                          },
                          AppRoute::UserDetails(username) => html! {
                              <div>
                              {"details about "} {&username}
                              </div>
                          },
                      }
                  })
                />
            </div>
        }
    }
}

impl App {
    fn get_redirect_route() -> Option<String> {
        let route_service = RouteService::<()>::new();
        let current_route = route_service.get_path();
        if current_route.is_empty() || current_route.contains("login") {
            None
        } else {
            Some(current_route)
        }
    }

    fn apply_initial_redirections(&mut self) {
        match &self.user_info {
            None => {
                ConsoleService::info("Redirecting to login");
                self.route_dispatcher
                    .send(RouteRequest::ReplaceRoute(Route::new_no_state("/login")));
            }
            Some((user_name, is_admin)) => match &self.redirect_to {
                Some(url) => {
                    ConsoleService::info(&format!("Redirecting to specified url: {}", url));
                    self.route_dispatcher
                        .send(RouteRequest::ReplaceRoute(Route::new_no_state(url)));
                }
                None => {
                    if *is_admin {
                        ConsoleService::info("Redirecting to user list");
                        self.route_dispatcher
                            .send(RouteRequest::ReplaceRoute(Route::new_no_state("/users")));
                    } else {
                        ConsoleService::info("Redirecting to user view");
                        self.route_dispatcher.send(RouteRequest::ReplaceRoute(
                            Route::new_no_state(&("/details/".to_string() + user_name)),
                        ));
                    }
                }
            },
        }
    }
}
