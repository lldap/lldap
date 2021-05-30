use crate::cookies::get_cookie;
use crate::login::LoginForm;
use crate::logout::LogoutButton;
use crate::user_table::UserTable;
use yew::prelude::*;
use yew::services::ConsoleService;
use yew_router::{
    agent::{RouteAgentDispatcher, RouteRequest},
    route::Route,
    router::Router,
    service::RouteService,
    Switch,
};

pub struct App {
    link: ComponentLink<Self>,
    user_name: Option<String>,
    redirect_to: String,
    route_dispatcher: RouteAgentDispatcher,
}

pub enum Msg {
    Login(String),
    Logout,
}

#[derive(Switch, Debug, Clone)]
pub enum AppRoute {
    #[to = "/login"]
    Login,
    #[to = "/users"]
    ListUsers,
    #[to = "/"]
    Index,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut app = Self {
            link,
            user_name: get_cookie("user_id").unwrap_or_else(|e| {
                ConsoleService::error(&e.to_string());
                None
            }),
            redirect_to: Self::get_redirect_route(),
            route_dispatcher: RouteAgentDispatcher::new(),
        };
        if app.user_name.is_none() {
            ConsoleService::info("Redirecting to login");
            app.route_dispatcher
                .send(RouteRequest::ReplaceRoute(Route::new_no_state("/login")));
        };
        app
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Login(user_name) => {
                self.user_name = Some(user_name);
                self.route_dispatcher
                    .send(RouteRequest::ChangeRoute(Route::new_no_state(
                        &self.redirect_to,
                    )));
            }
            Msg::Logout => {
                self.user_name = None;
            }
        }
        if self.user_name.is_none() {
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
                          AppRoute::Index | AppRoute::ListUsers => html! {
                              <div>
                                <LogoutButton on_logged_out=link.callback(|_| Msg::Logout) />
                                <UserTable />
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
    fn get_redirect_route() -> String {
        let route_service = RouteService::<()>::new();
        let current_route = route_service.get_path();
        if current_route.is_empty() || current_route.contains("login") {
            String::from("/")
        } else {
            current_route
        }
    }
}
