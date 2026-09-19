use crate::components::{
    avatar::Avatar,
    logout::LogoutButton,
    router::{AppRoute, Link},
};
use wasm_bindgen::prelude::wasm_bindgen;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub is_admin: bool,
    pub username: Option<String>,
    pub on_logged_out: Callback<()>,
}

#[function_component(Banner)]
pub fn banner(props: &Props) -> Html {
    html! {
      <header class="app-header border-bottom mb-4">
        <div class="container">
          <div class="d-flex flex-wrap align-items-center justify-content-center justify-content-lg-between gap-2 py-2">
            <a href={yew_router::utils::base_url().unwrap_or("/".to_string())} class="app-brand d-flex align-items-center text-decoration-none">
              <span class="app-brand-name">{"LLDAP"}</span>
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

#[function_component(DarkModeToggle)]
fn dark_mode_toggle() -> Html {
    let dark_state = use_state(inDarkMode);
    let onclick = {
        let dark_state = dark_state.clone();
        Callback::from(move |_| {
            toggleDarkMode();
            dark_state.set(inDarkMode());
        })
    };
    let current_is_dark = inDarkMode();
    let (icon, label) = if current_is_dark {
        ("bi-sun-fill", "Switch to light mode")
    } else {
        ("bi-moon-stars-fill", "Switch to dark mode")
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
