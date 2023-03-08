use crate::{
    components::{
        change_password::ChangePasswordForm,
        create_group::CreateGroupForm,
        create_user::CreateUserForm,
        group_details::GroupDetails,
        group_table::GroupTable,
        login::LoginForm,
        logout::LogoutButton,
        reset_password_step1::ResetPasswordStep1Form,
        reset_password_step2::ResetPasswordStep2Form,
        router::{AppRoute, Link, NavButton},
        user_details::UserDetails,
        user_table::UserTable,
    },
    infra::{api::HostService, cookies::get_cookie},
};

use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};
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
    password_reset_enabled: Option<bool>,
    task: Option<FetchTask>,
}

pub enum Msg {
    Login((String, bool)),
    Logout,
    PasswordResetProbeFinished(anyhow::Result<bool>),
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
            password_reset_enabled: None,
            task: None,
        };
        app.task = Some(
            HostService::probe_password_reset(
                app.link.callback_once(Msg::PasswordResetProbeFinished),
            )
            .unwrap(),
        );
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
                self.route_dispatcher
                    .send(RouteRequest::ReplaceRoute(Route::from(AppRoute::Login)));
            }
            Msg::PasswordResetProbeFinished(Ok(enabled)) => {
                self.task = None;
                self.password_reset_enabled = Some(enabled);
            }
            Msg::PasswordResetProbeFinished(Err(err)) => {
                self.task = None;
                self.password_reset_enabled = Some(false);
                ConsoleService::error(&format!(
                    "Could not probe for password reset support: {err:#}"
                ));
            }
        }
        true
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        let link = self.link.clone();
        let is_admin = self.is_admin();
        let password_reset_enabled = self.password_reset_enabled;
        html! {
          <div>
            {self.view_banner()}
            <div class="container py-3 bg-kug">
              <div class="row justify-content-center" style="padding-bottom: 80px;">
                <div class="py-3" style="max-width: 1000px">
                  <Router<AppRoute>
                    render={Router::render(move |s| Self::dispatch_route(s, &link, is_admin, password_reset_enabled))}
                  />
                </div>
              </div>
              {self.view_footer()}
            </div>
          </div>
        }
    }
}

impl App {
    fn get_redirect_route() -> Option<AppRoute> {
        let route_service = RouteService::<()>::new();
        let current_route = route_service.get_path();
        if current_route.is_empty()
            || current_route == "/"
            || current_route.contains("login")
            || current_route.contains("reset-password")
        {
            None
        } else {
            use yew_router::Switch;
            AppRoute::from_route_part::<()>(current_route, None).0
        }
    }

    fn apply_initial_redirections(&mut self) {
        let route_service = RouteService::<()>::new();
        let current_route = route_service.get_path();
        if current_route.contains("reset-password") {
            if self.password_reset_enabled == Some(false) {
                self.route_dispatcher
                    .send(RouteRequest::ReplaceRoute(Route::from(AppRoute::Login)));
            }
            return;
        }
        match &self.user_info {
            None => {
                self.route_dispatcher
                    .send(RouteRequest::ReplaceRoute(Route::from(AppRoute::Login)));
            }
            Some((user_name, is_admin)) => match &self.redirect_to {
                Some(url) => {
                    self.route_dispatcher
                        .send(RouteRequest::ReplaceRoute(Route::from(url.clone())));
                }
                None => {
                    if *is_admin {
                        self.route_dispatcher
                            .send(RouteRequest::ReplaceRoute(Route::from(AppRoute::ListUsers)));
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

    fn dispatch_route(
        switch: AppRoute,
        link: &ComponentLink<Self>,
        is_admin: bool,
        password_reset_enabled: Option<bool>,
    ) -> Html {
        match switch {
            AppRoute::Login => html! {
                <LoginForm on_logged_in={link.callback(Msg::Login)} password_reset_enabled={password_reset_enabled.unwrap_or(false)}/>
            },
            AppRoute::CreateUser => html! {
                <CreateUserForm/>
            },
            AppRoute::Index | AppRoute::ListUsers => html! {
                <div>
                  <UserTable />
                  <NavButton classes="btn btn-primary" route={AppRoute::CreateUser}>
                    <i class="bi-person-plus me-2"></i>
                    {"Create a user"}
                  </NavButton>
                </div>
            },
            AppRoute::CreateGroup => html! {
                <CreateGroupForm/>
            },
            AppRoute::ListGroups => html! {
                <div>
                  <GroupTable />
                  <NavButton classes="btn btn-primary" route={AppRoute::CreateGroup}>
                    <i class="bi-plus-circle me-2"></i>
                    {"Create a group"}
                  </NavButton>
                </div>
            },
            AppRoute::GroupDetails(group_id) => html! {
                <GroupDetails group_id={group_id} />
            },
            AppRoute::UserDetails(username) => html! {
                <UserDetails username={username} is_admin={is_admin} />
            },
            AppRoute::ChangePassword(username) => html! {
                <ChangePasswordForm username={username} is_admin={is_admin} />
            },
            AppRoute::StartResetPassword => match password_reset_enabled {
                Some(true) => html! { <ResetPasswordStep1Form /> },
                Some(false) => {
                    App::dispatch_route(AppRoute::Login, link, is_admin, password_reset_enabled)
                }

                None => html! {},
            },
            AppRoute::FinishResetPassword(token) => match password_reset_enabled {
                Some(true) => html! { <ResetPasswordStep2Form token={token} /> },
                Some(false) => {
                    App::dispatch_route(AppRoute::Login, link, is_admin, password_reset_enabled)
                }
                None => html! {},
            },
        }
    }

    fn view_banner(&self) -> Html {
        let link = &self.link;
        html! {
          <header class="p-2 mb-3 border-bottom">
            <div class="container">
              <div class="d-flex flex-wrap align-items-center justify-content-center justify-content-lg-start">
                <a href="/" class="d-flex align-items-center mt-2 mb-lg-0 me-md-5 text-dark text-decoration-none">
                  <h2>{"LLDAP"}</h2>
                </a>

                <ul class="nav col-12 col-lg-auto me-lg-auto mb-2 justify-content-center mb-md-0">
                  {if self.is_admin() { html! {
                    <>
                      <li>
                        <Link
                          classes="nav-link px-2 link-dark h6"
                          route={AppRoute::ListUsers}>
                          <i class="bi-people me-2"></i>
                          {"Users"}
                        </Link>
                      </li>
                      <li>
                        <Link
                          classes="nav-link px-2 link-dark h6"
                          route={AppRoute::ListGroups}>
                          <i class="bi-collection me-2"></i>
                          {"Groups"}
                        </Link>
                      </li>
                    </>
                  } } else { html!{} } }
                </ul>

                {
                  if let Some((user_id, _)) = &self.user_info {
                    html! {
                      <div class="dropdown text-end">
                        <a href="#"
                          class="d-block link-dark text-decoration-none dropdown-toggle"
                          id="dropdownUser"
                          data-bs-toggle="dropdown"
                          aria-expanded="false">
                          <svg xmlns="http://www.w3.org/2000/svg"
                            width="32"
                            height="32"
                            fill="currentColor"
                            class="bi bi-person-circle"
                            viewBox="0 0 16 16">
                            <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
                            <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
                          </svg>
                          <span class="ms-2">
                            {user_id}
                          </span>
                        </a>
                        <ul
                          class="dropdown-menu text-small dropdown-menu-lg-end"
                          aria-labelledby="dropdownUser1"
                          style="">
                          <li>
                            <Link
                              classes="dropdown-item"
                              route={AppRoute::UserDetails(user_id.clone())}>
                              {"View details"}
                            </Link>
                          </li>
                          <li><hr class="dropdown-divider" /></li>
                          <li>
                            <LogoutButton on_logged_out={link.callback(|_| Msg::Logout)} />
                          </li>
                        </ul>
                      </div>
                    }
                  } else { html!{} }
                }
              </div>
            </div>
          </header>
        }
    }

    fn view_footer(&self) -> Html {
        html! {
          <footer class="text-center text-muted fixed-bottom bg-light py-2">
            <div>
              <span>{format!("LLDAP version {}", env!("CARGO_PKG_VERSION"))}</span>
            </div>
            <div>
              <a href="https://github.com/nitnelave/lldap" class="me-4 text-reset">
                <i class="bi-github"></i>
              </a>
              <a href="https://discord.gg/h5PEdRMNyP" class="me-4 text-reset">
                <i class="bi-discord"></i>
              </a>
              <a href="https://twitter.com/nitnelave1?ref_src=twsrc%5Etfw" class="me-4 text-reset">
                <i class="bi-twitter"></i>
              </a>
            </div>
            <div>
              <span>{"License "}<a href="https://github.com/nitnelave/lldap/blob/main/LICENSE" class="link-secondary">{"GNU GPL"}</a></span>
            </div>
          </footer>
        }
    }

    fn is_admin(&self) -> bool {
        match &self.user_info {
            None => false,
            Some((_, is_admin)) => *is_admin,
        }
    }
}
