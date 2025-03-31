use crate::components::{
    avatar::Avatar,
    logout::LogoutButton,
    router::{AppRoute, Link},
};
use wasm_bindgen::prelude::wasm_bindgen;
use yew::{Callback, Properties, function_component, html};

#[derive(Properties, PartialEq)]
pub struct Props {
    pub is_admin: bool,
    pub username: Option<String>,
    pub on_logged_out: Callback<()>,
}

#[function_component(Banner)]
pub fn banner(props: &Props) -> Html {
    html! {
      <header class="p-2 mb-3 border-bottom">
        <div class="container">
          <div class="d-flex flex-wrap align-items-center justify-content-center justify-content-lg-start">
            <a href={yew_router::utils::base_url().unwrap_or("/".to_string())} class="d-flex align-items-center mt-2 mb-lg-0 me-md-5 text-decoration-none">
              <h2>{"LLDAP"}</h2>
            </a>

            <ul class="nav col-12 col-lg-auto me-lg-auto mb-2 justify-content-center mb-md-0">
              {if props.is_admin { html! {
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
                  <li>
                    <Link
                      classes="nav-link px-2 h6"
                      to={AppRoute::ListUserSchema}>
                      <i class="bi-list-ul me-2"></i>
                      {"User schema"}
                    </Link>
                  </li>
                  <li>
                    <Link
                      classes="nav-link px-2 h6"
                      to={AppRoute::ListGroupSchema}>
                      <i class="bi-list-ul me-2"></i>
                      {"Group schema"}
                    </Link>
                  </li>
                </>
              } } else { html!{} } }
            </ul>
            <UserMenu username={props.username.clone()} on_logged_out={props.on_logged_out.clone()}/>
            <DarkModeToggle />
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
              class="d-block nav-link text-decoration-none dropdown-toggle"
              id="dropdownUser"
              data-bs-toggle="dropdown"
              aria-expanded="false">
              <Avatar user={username.clone()} />
              <span class="ms-2">
                {username}
              </span>
            </a>
            <ul
              class="dropdown-menu text-small dropdown-menu-lg-end"
              aria-labelledby="dropdownUser1"
              style="">
              <li>
                <Link
                  classes="dropdown-item"
                  to={AppRoute::UserDetails{ user_id: username.to_string() }}>
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
    #[wasm_bindgen(js_namespace = darkmode)]
    fn toggleDarkMode(doSave: bool);

    #[wasm_bindgen]
    fn inDarkMode() -> bool;
}

#[function_component(DarkModeToggle)]
fn dark_mode_toggle() -> Html {
    html! {
      <div class="form-check form-switch">
        <input class="form-check-input" onclick={|_| toggleDarkMode(true)} type="checkbox" id="darkModeToggle" checked={inDarkMode()}/>
        <label class="form-check-label" for="darkModeToggle">{"Dark mode"}</label>
      </div>
    }
}
