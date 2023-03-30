use crate::components::avatar_cache::AvatarCacheContext;
use yew::{function_component, prelude::*};

#[derive(Properties, PartialEq)]
pub struct Props {
    pub username: String,
    pub width: i32,
    pub height: i32,
}

#[function_component(ShowAvatar)]
pub fn show_avatar(props: &Props) -> Html {
    let cache = use_context::<AvatarCacheContext>().expect("no ctx found");
    let avatar = cache
        .avatars
        .get(&props.username)
        .map(|val| val.clone())
        .unwrap_or(None);
    match avatar {
        Some(avatar) => html! {
            <img
                    class="avatar"
                    src={format!("data:image/jpeg;base64, {}", avatar)}
                    style={format!("max-height:{}px;max-width:{}px;height:auto;width:auto;", props.height, props.width)}
                    alt="Avatar" />
        },
        None => html! {
            <svg xmlns="http://www.w3.org/2000/svg"
                    width={props.width.to_string()}
                    height={props.height.to_string()}
                    fill="currentColor"
                    class="bi bi-person-circle"
                    viewBox="0 0 16 16">
                    <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
                    <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
                </svg>
        },
    }
}
