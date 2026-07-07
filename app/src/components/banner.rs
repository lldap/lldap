use crate::components::{
    avatar::Avatar,
    logout::LogoutButton,
    router::{AppRoute, Link},
};
use lldap_frontend_options::BrandingOptions;
use wasm_bindgen::prelude::wasm_bindgen;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub is_admin: bool,
    pub username: Option<String>,
    pub branding: Option<BrandingOptions>,
    pub on_logged_out: Callback<()>,
}

#[function_component(Banner)]
pub fn banner(props: &Props) -> Html {
    let app_name = props
        .branding
        .as_ref()
        .map_or_else(|| "LLDAP".to_string(), |branding| branding.app_name.clone());
    let logo_file_has_been_uploaded = props
        .branding
        .as_ref()
        .is_some_and(|branding| branding.logo_file_has_been_uploaded);
    let logo_url = props
        .branding
        .as_ref()
        .and_then(|branding| branding.logo_url.clone());

    let logo_html = if logo_file_has_been_uploaded {
        html! {
            <img src="/branding/logo" alt="Logo" class="app-brand-logo-image" />
        }
    } else if let Some(logo_url) = logo_url {
        html! {
            <img src={logo_url.clone()} alt="Logo" class="app-brand-logo-image" />
        }
    } else {
        html! {
            <span class="app-brand-logo"><i class="bi-shield-lock-fill"></i></span>
        }
    };

    html! {
      <header class="app-header border-bottom mb-4">
        <div class="container">
          <div class="d-flex flex-wrap align-items-center justify-content-center justify-content-lg-between gap-2 py-2">
            <a href={yew_router::utils::base_url().unwrap_or("/".to_string())} class="app-brand d-flex align-items-center text-decoration-none">
              {logo_html}
              <span class="app-brand-name">{app_name}</span>
            </a>

            <ul class="nav app-nav justify-content-center flex-grow-1">
              {if props.is_admin { html! {
                <>
                  <li class="nav-item">
                    <Link
                      classes="nav-link"
                      to={AppRoute::ListUsers}>
                      <i class="bi-people me-2"></i>
                      {"Users"}
                    </Link>
                  </li>
                  <li class="nav-item">
                    <Link
                      classes="nav-link"
                      to={AppRoute::ListGroups}>
                      <i class="bi-collection me-2"></i>
                      {"Groups"}
                    </Link>
                  </li>
                  <li class="nav-item">
                    <Link
                      classes="nav-link"
                      to={AppRoute::ListUserSchema}>
                      <i class="bi-list-ul me-2"></i>
                      {"User schema"}
                    </Link>
                  </li>
                  <li class="nav-item">
                    <Link
                      classes="nav-link"
                      to={AppRoute::ListGroupSchema}>
                      <i class="bi-list-ul me-2"></i>
                      {"Group schema"}
                    </Link>
                  </li>
                  <li class="nav-item">
                    <Link
                      classes="nav-link"
                      to={AppRoute::AdminSettings}>
                      <i class="bi-gear me-2"></i>
                      {"Settings"}
                    </Link>
                  </li>
                </>
              } } else { html!{} } }
            </ul>

            <div class="d-flex align-items-center gap-2">
              <DarkModeToggle />
              <UserMenu username={props.username.clone()} on_logged_out={props.on_logged_out.clone()}/>
            </div>
          </div>
        </div>
      </header>
    }
}

#[derive(Properties, PartialEq)]
struct UserMenuProps {
    pub username: Option<String>,
    pub on_logged_out: Callback<()>,
}

#[function_component(UserMenu)]
fn user_menu(props: &UserMenuProps) -> Html {
    match &props.username {
        Some(username) => html! {
          <div class="dropdown text-end">
            <a href="#"
              class="d-flex align-items-center text-decoration-none dropdown-toggle app-user-menu"
              id="dropdownUser"
              data-bs-toggle="dropdown"
              aria-expanded="false">
              <Avatar user={username.clone()} />
              <span class="ms-2 d-none d-sm-inline">
                {username}
              </span>
            </a>
            <ul
              class="dropdown-menu dropdown-menu-end shadow-sm"
              aria-labelledby="dropdownUser">
              <li>
                <Link
                  classes="dropdown-item"
                  to={AppRoute::UserDetails{ user_id: username.to_string() }}>
                  <i class="bi-person me-2"></i>
                  {"View details"}
                </Link>
              </li>
              <li><hr class="dropdown-divider" /></li>
              <li>
                <LogoutButton on_logged_out={props.on_logged_out.clone()} />
              </li>
            </ul>
          </div>
        },
        _ => html! {},
    }
}

#[wasm_bindgen]
extern "C" {
    /// Flips the `data-bs-theme` attribute on `<html>` and persists the choice.
    /// Defined as a global function in `index.html` / `index_local.html`.
    fn toggleDarkMode();

    /// Reads whether the document is currently in dark mode.
    fn inDarkMode() -> bool;
}

/// Bootstrap Icons class shown when dark mode is active (offers to switch to light).
const LIGHT_MODE_ICON: &str = "bi-sun-fill";
/// Bootstrap Icons class shown when light mode is active (offers to switch to dark).
const DARK_MODE_ICON: &str = "bi-moon-stars-fill";
const SWITCH_TO_LIGHT_LABEL: &str = "Switch to light mode";
const SWITCH_TO_DARK_LABEL: &str = "Switch to dark mode";

#[function_component(DarkModeToggle)]
fn dark_mode_toggle() -> Html {
    let is_dark = use_state(inDarkMode);
    let onclick = {
        let is_dark = is_dark.clone();
        Callback::from(move |_| {
            toggleDarkMode();
            is_dark.set(inDarkMode());
        })
    };
    let (icon, label) = if *is_dark {
        (LIGHT_MODE_ICON, SWITCH_TO_LIGHT_LABEL)
    } else {
        (DARK_MODE_ICON, SWITCH_TO_DARK_LABEL)
    };
    html! {
      <button
        type="button"
        class="btn btn-outline-secondary btn-icon theme-toggle"
        onclick={onclick}
        title={label}
        aria-label={label}>
        <i class={classes!(icon)}></i>
      </button>
    }
}
