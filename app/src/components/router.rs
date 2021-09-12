use yew_router::{
    components::{RouterAnchor, RouterButton},
    Switch,
};

#[derive(Switch, Debug, Clone)]
pub enum AppRoute {
    #[to = "/login"]
    Login,
    #[to = "/users"]
    ListUsers,
    #[to = "/users/create"]
    CreateUser,
    #[to = "/user/{user_id}/password"]
    ChangePassword(String),
    #[to = "/user/{user_id}"]
    UserDetails(String),
    #[to = "/"]
    Index,
}

pub type Link = RouterAnchor<AppRoute>;

pub type NavButton = RouterButton<AppRoute>;
