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
        router::{AppRoute, Link, Redirect},
        user_details::UserDetails,
        user_table::UserTable,
    },
    infra::{api::HostService, cookies::get_cookie},
};

use gloo_console::error;
use wasm_bindgen::prelude::*;
use yew::{
    function_component,
    html::Scope,
    prelude::{html, Component, Html},
    Context,
};
use yew_router::{
    prelude::{History, Location},
    scope_ext::RouterScopeExt,
    BrowserRouter, Switch,
};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = darkmode)]
    fn toggleDarkMode(doSave: bool);

    #[wasm_bindgen]
    fn inDarkMode() -> bool;
}

#[function_component(DarkModeToggle)]
pub fn dark_mode_toggle() -> Html {
    html! {
      <div class="form-check form-switch">
        <input class="form-check-input" onclick={|_| toggleDarkMode(true)} type="checkbox" id="darkModeToggle" checked={inDarkMode()}/>
        <label class="form-check-label" for="darkModeToggle">{"Dark mode"}</label>
      </div>
    }
}

#[function_component(AppContainer)]
pub fn app_container() -> Html {
    html! {
        <BrowserRouter>
            <App />
        </BrowserRouter>
    }
}

pub struct App {
    user_info: Option<(String, bool)>,
    redirect_to: Option<AppRoute>,
    password_reset_enabled: Option<bool>,
}

pub enum Msg {
    Login((String, bool)),
    Logout,
    PasswordResetProbeFinished(anyhow::Result<bool>),
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let app = Self {
            user_info: get_cookie("user_id")
                .unwrap_or_else(|e| {
                    error!(&e.to_string());
                    None
                })
                .and_then(|u| {
                    get_cookie("is_admin")
                        .map(|so| so.map(|s| (u, s == "true")))
                        .unwrap_or_else(|e| {
                            error!(&e.to_string());
                            None
                        })
                }),
            redirect_to: Self::get_redirect_route(ctx),
            password_reset_enabled: None,
        };
        ctx.link().send_future(async move {
            Msg::PasswordResetProbeFinished(HostService::probe_password_reset().await)
        });
        app.apply_initial_redirections(ctx);
        app
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        let history = ctx.link().history().unwrap();
        match msg {
            Msg::Login((user_name, is_admin)) => {
                self.user_info = Some((user_name.clone(), is_admin));
                history.push(self.redirect_to.take().unwrap_or_else(|| {
                    if is_admin {
                        AppRoute::ListUsers
                    } else {
                        AppRoute::UserDetails {
                            user_id: user_name.clone(),
                        }
                    }
                }));
            }
            Msg::Logout => {
                self.user_info = None;
                self.redirect_to = None;
                history.push(AppRoute::Login);
            }
            Msg::PasswordResetProbeFinished(Ok(enabled)) => {
                self.password_reset_enabled = Some(enabled);
            }
            Msg::PasswordResetProbeFinished(Err(err)) => {
                self.password_reset_enabled = Some(false);
                error!(&format!(
                    "Could not probe for password reset support: {err:#}"
                ));
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link().clone();
        let is_admin = self.is_admin();
        let password_reset_enabled = self.password_reset_enabled;
        html! {
          <div>
            {self.view_banner(ctx)}
            <div class="container py-3 bg-kug">
              <div class="row justify-content-center" style="padding-bottom: 80px;">
                <main class="py-3" style="max-width: 1000px">
                  <Switch<AppRoute>
                    render={Switch::render(move |routes| Self::dispatch_route(routes, &link, is_admin, password_reset_enabled))}
                  />
                </main>
              </div>
              {self.view_footer()}
            </div>
          </div>
        }
    }
}

impl App {
    // Get the page to land on after logging in, defaulting to the index.
    fn get_redirect_route(ctx: &Context<Self>) -> Option<AppRoute> {
        let route = ctx.link().history().unwrap().location().route::<AppRoute>();
        route.filter(|route| {
            !matches!(
                route,
                AppRoute::Index
                    | AppRoute::Login
                    | AppRoute::StartResetPassword
                    | AppRoute::FinishResetPassword { token: _ }
            )
        })
    }

    fn apply_initial_redirections(&self, ctx: &Context<Self>) {
        let history = ctx.link().history().unwrap();
        let route = history.location().route::<AppRoute>();
        let redirection = match (route, &self.user_info, &self.redirect_to) {
            (
                Some(AppRoute::StartResetPassword | AppRoute::FinishResetPassword { token: _ }),
                _,
                _,
            ) => {
                if self.password_reset_enabled == Some(false) {
                    Some(AppRoute::Login)
                } else {
                    None
                }
            }
            (None, _, _) | (_, None, _) => Some(AppRoute::Login),
            // User is logged in, a URL was given, don't redirect.
            (_, Some(_), Some(_)) => None,
            (_, Some((user_name, is_admin)), None) => {
                if *is_admin {
                    Some(AppRoute::ListUsers)
                } else {
                    Some(AppRoute::UserDetails {
                        user_id: user_name.clone(),
                    })
                }
            }
        };
        if let Some(redirect_to) = redirection {
            history.push(redirect_to);
        }
    }

    fn dispatch_route(
        switch: &AppRoute,
        link: &Scope<Self>,
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
                  <Link classes="btn btn-primary" to={AppRoute::CreateUser}>
                    <i class="bi-person-plus me-2"></i>
                    {"Create a user"}
                  </Link>
                </div>
            },
            AppRoute::CreateGroup => html! {
                <CreateGroupForm/>
            },
            AppRoute::ListGroups => html! {
                <div>
                  <GroupTable />
                  <Link classes="btn btn-primary" to={AppRoute::CreateGroup}>
                    <i class="bi-plus-circle me-2"></i>
                    {"Create a group"}
                  </Link>
                </div>
            },
            AppRoute::GroupDetails { group_id } => html! {
                <GroupDetails group_id={*group_id} />
            },
            AppRoute::UserDetails { user_id } => html! {
                <UserDetails username={user_id.clone()} is_admin={is_admin} />
            },
            AppRoute::ChangePassword { user_id } => html! {
                <ChangePasswordForm username={user_id.clone()} is_admin={is_admin} />
            },
            AppRoute::StartResetPassword => match password_reset_enabled {
                Some(true) => html! { <ResetPasswordStep1Form /> },
                Some(false) => {
                    html! { <Redirect to={AppRoute::Login}/> }
                }

                None => html! {},
            },
            AppRoute::FinishResetPassword { token } => match password_reset_enabled {
                Some(true) => html! { <ResetPasswordStep2Form token={token.clone()} /> },
                Some(false) => {
                    html! { <Redirect to={AppRoute::Login}/> }
                }
                None => html! {},
            },
        }
    }

    fn view_banner(&self, ctx: &Context<Self>) -> Html {
        html! {
          <header class="p-2 mb-3 border-bottom">
            <div class="container">
              <div class="d-flex flex-wrap align-items-center justify-content-center justify-content-lg-start">
                <a href="/" class="d-flex align-items-center mt-2 mb-lg-0 me-md-5 text-decoration-none">
                  <h2>{"LLDAP"}</h2>
                </a>

                <ul class="nav col-12 col-lg-auto me-lg-auto mb-2 justify-content-center mb-md-0">
                  {if self.is_admin() { html! {
                    <>
                      <li>
                        <Link
                          classes="nav-link px-2 h6"
                          to={AppRoute::ListUsers}>
                          <i class="bi-people me-2"></i>
                          {"Users"}
                        </Link>
                      </li>
                      <li>
                        <Link
                          classes="nav-link px-2 h6"
                          to={AppRoute::ListGroups}>
                          <i class="bi-collection me-2"></i>
                          {"Groups"}
                        </Link>
                      </li>
                    </>
                  } } else { html!{} } }
                </ul>
                { self.view_user_menu(ctx) }
                <DarkModeToggle />
              </div>
            </div>
          </header>
        }
    }

    fn view_user_menu(&self, ctx: &Context<Self>) -> Html {
        if let Some((user_id, _)) = &self.user_info {
            let link = ctx.link();
            html! {
              <div class="dropdown text-end">
                <a href="#"
                  class="d-block nav-link text-decoration-none dropdown-toggle"
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
                      to={AppRoute::UserDetails{ user_id: user_id.clone() }}>
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
        } else {
            html! {}
        }
    }

    fn view_footer(&self) -> Html {
        html! {
          <footer class="text-center fixed-bottom text-muted bg-light py-2">
            <div>
              <span>{format!("LLDAP version {}", env!("CARGO_PKG_VERSION"))}</span>
            </div>
            <div>
              <a href="https://github.com/lldap/lldap" class="me-4 text-reset">
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
              <span>{"License "}<a href="https://github.com/lldap/lldap/blob/main/LICENSE" class="link-secondary">{"GNU GPL"}</a></span>
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
