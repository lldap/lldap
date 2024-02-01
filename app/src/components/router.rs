use yew_router::Routable;

#[derive(Routable, Debug, Clone, PartialEq)]
pub enum AppRoute {
    #[at("/login")]
    Login,
    #[at("/reset-password/step1")]
    StartResetPassword,
    #[at("/reset-password/step2/:token")]
    FinishResetPassword { token: String },
    #[at("/users/create")]
    CreateUser,
    #[at("/users")]
    ListUsers,
    #[at("/user/:user_id/password")]
    ChangePassword { user_id: String },
    #[at("/user/:user_id")]
    UserDetails { user_id: String },
    #[at("/groups/create")]
    CreateGroup,
    #[at("/groups")]
    ListGroups,
    #[at("/group/:group_id")]
    GroupDetails { group_id: i64 },
    #[at("/user-attributes")]
    ListUserSchema,
    #[at("/user-attributes/create")]
    CreateUserAttribute,
    #[at("/group-attributes")]
    ListGroupSchema,
    #[at("/group-attributes/create")]
    CreateGroupAttribute,
    #[at("/")]
    Index,
}

pub type Link = yew_router::components::Link<AppRoute>;
pub type Redirect = yew_router::components::Redirect<AppRoute>;
