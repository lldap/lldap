use crate::{
    components::{
        banner::Banner,
        change_password::ChangePasswordForm,
        create_group::CreateGroupForm,
        create_group_attribute::CreateGroupAttributeForm,
        create_user::CreateUserForm,
        create_user_attribute::CreateUserAttributeForm,
        group_details::GroupDetails,
        group_schema_table::ListGroupSchema,
        group_table::GroupTable,
        login::LoginForm,
        reset_password_step1::ResetPasswordStep1Form,
        reset_password_step2::ResetPasswordStep2Form,
        router::{AppRoute, Link, Redirect},
        user_details::UserDetails,
        user_schema_table::ListUserSchema,
        user_table::UserTable,
    },
    infra::{api::HostService, cookies::get_cookie},
};

use gloo_console::error;
use lldap_frontend_options::{BrandingOptions, Options, ThemeMode};
use wasm_bindgen::prelude::wasm_bindgen;
use yew::{
    Context, function_component,
    html::Scope,
    prelude::{Component, Html, html},
};
use yew_router::{
    BrowserRouter, Switch,
    prelude::{History, Location},
    scope_ext::RouterScopeExt,
};

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
    branding: Option<BrandingOptions>,
}

pub enum Msg {
    Login((String, bool)),
    Logout,
    SettingsReceived(anyhow::Result<Options>),
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
            branding: None,
        };
        ctx.link()
            .send_future(async move { Msg::SettingsReceived(HostService::get_settings().await) });
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
            Msg::SettingsReceived(Ok(settings)) => {
                self.password_reset_enabled = Some(settings.password_reset_enabled);
                let branding = settings.branding;
                // Apply document title.
                if let Some(window) = web_sys::window()
                    && let Some(document) = window.document()
                {
                    document.set_title(&branding.app_name);
                }
                // Set accent CSS custom property via JS shim in index.html.
                if let Some(ref color) = branding.accent_color {
                    set_theme_accent(color);
                }
                // Apply server-configured default theme only when the user has no
                // explicit stored preference.
                let has_stored_theme = web_sys::window()
                    .and_then(|w| w.local_storage().ok().flatten())
                    .and_then(|storage| storage.get_item("theme").ok().flatten())
                    .is_some();
                if !has_stored_theme {
                    match branding.default_theme {
                        ThemeMode::Light => apply_theme("light"),
                        ThemeMode::Dark => apply_theme("dark"),
                        ThemeMode::Auto => { /* let the inline script's media-query fallback stand */
                        }
                    }
                }
                self.branding = Some(branding);
            }
            Msg::SettingsReceived(Err(err)) => {
                error!(err.to_string());
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link().clone();
        let is_admin = self.is_admin();
        let username = self.user_info.clone().map(|(username, _)| username);
        let password_reset_enabled = self.password_reset_enabled;
        let app_name = self
            .branding
            .as_ref()
            .map_or_else(|| "LLDAP".to_string(), |b| b.app_name.clone());
        let branding = self.branding.clone();
        html! {
          <div class="d-flex flex-column min-vh-100">
            <Banner is_admin={is_admin} username={username} branding={branding.clone()} on_logged_out={link.callback(|_| Msg::Logout)} />
            <main class="container app-content flex-grow-1">
              <Switch<AppRoute>
                render={Switch::render(move |routes| Self::dispatch_route(routes, &link, is_admin, password_reset_enabled, app_name.clone()))}
              />
            </main>
            {self.view_footer()}
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

    /// Percent-decode a URL path segment into a user ID string.
    /// Returns `None` if the decoded bytes are not valid UTF-8, so the caller
    /// can redirect to a safe page rather than silently mangling the ID.
    fn decode_user_id(raw: &str) -> Option<String> {
        percent_encoding::percent_decode_str(raw)
            .decode_utf8()
            .ok()
            .map(|s| s.into_owned())
    }

    fn dispatch_route(
        switch: &AppRoute,
        link: &Scope<Self>,
        is_admin: bool,
        password_reset_enabled: Option<bool>,
        app_name: String,
    ) -> Html {
        match switch {
            AppRoute::Login => {
                html! {
                    <LoginForm
                        on_logged_in={link.callback(Msg::Login)}
                        password_reset_enabled={password_reset_enabled.unwrap_or(false)}
                        app_name={app_name.clone()}
                    />
                }
            },
            AppRoute::CreateUser => html! {
                <CreateUserForm/>
            },
            AppRoute::Index | AppRoute::ListUsers => {
                html! {
                  <div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between mb-3 gap-2">
                      <h1 class="h3 mb-0">{"Users"}</h1>
                      <Link classes="btn btn-primary" to={AppRoute::CreateUser}>
                        <i class="bi-person-plus me-2"></i>
                        {"Create a user"}
                      </Link>
                    </div>
                    <UserTable />
                  </div>
                }
            }
            AppRoute::CreateGroup => html! {
                <CreateGroupForm/>
            },
            AppRoute::CreateUserAttribute => html! {
                <CreateUserAttributeForm/>
            },
            AppRoute::CreateGroupAttribute => html! {
                <CreateGroupAttributeForm/>
            },
            AppRoute::AdminSettings => html! {
                <crate::components::admin_settings::AdminSettingsForm />
            },
            AppRoute::ListGroups => {
                html! {
                  <div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between mb-3 gap-2">
                      <h1 class="h3 mb-0">{"Groups"}</h1>
                      <Link classes="btn btn-primary" to={AppRoute::CreateGroup}>
                        <i class="bi-plus-circle me-2"></i>
                        {"Create a group"}
                      </Link>
                    </div>
                    <GroupTable />
                  </div>
                }
            }
            AppRoute::ListUserSchema => html! {
                <ListUserSchema />
            },
            AppRoute::ListGroupSchema => html! {
                <ListGroupSchema />
            },
            AppRoute::GroupDetails { group_id } => html! {
                <GroupDetails group_id={*group_id} is_admin={is_admin} />
            },
            AppRoute::UserDetails { user_id } => match Self::decode_user_id(user_id) {
                Some(decoded_id) => html! {
                    <UserDetails username={decoded_id} is_admin={is_admin} />
                },
                None => html! { <Redirect to={AppRoute::Login} /> },
            },
            AppRoute::ChangePassword { user_id } => match Self::decode_user_id(user_id) {
                Some(decoded_id) => html! {
                    <ChangePasswordForm username={decoded_id} is_admin={is_admin} />
                },
                None => html! { <Redirect to={AppRoute::Login} /> },
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

    fn view_footer(&self) -> Html {
        html! {
          <footer class="app-footer text-center mt-4">
            <div>
              <span>{format!("LLDAP version {}", env!("CARGO_PKG_VERSION"))}</span>
            </div>
            <div>
              <a href="https://github.com/lldap/lldap" aria-label="GitHub">
                <i class="bi-github"></i>
              </a>
              <a href="https://discord.gg/h5PEdRMNyP" aria-label="Discord">
                <i class="bi-discord"></i>
              </a>
              <a href="https://twitter.com/nitnelave1?ref_src=twsrc%5Etfw" aria-label="Twitter">
                <i class="bi-twitter"></i>
              </a>
            </div>
            <div>
              <span>{"License "}<a href="https://github.com/lldap/lldap/blob/main/LICENSE">{"GNU GPL"}</a></span>
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

/// Called by the server-provided branding options to set the
/// `--lldap-accent` CSS custom property on `<html>`.
#[wasm_bindgen]
extern "C" {
    fn setThemeAccent(color: &str);
}

fn set_theme_accent(color: &str) {
    setThemeAccent(color);
}

/// Set `data-bs-theme` on `<html>` and persist it to localStorage.
fn apply_theme(theme: &str) {
    if let Some(window) = web_sys::window()
        && let Some(document) = window.document()
        && let Some(html) = document.document_element()
    {
        let _ = html.set_attribute("data-bs-theme", theme);
    }
    if let Some(window) = web_sys::window()
        && let Ok(Some(storage)) = window.local_storage()
    {
        let _ = storage.set_item("theme", theme);
    }
}
