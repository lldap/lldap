use crate::infra::common_component::{CommonComponent, CommonComponentParts};
use anyhow::{bail, Result};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_avatar.graphql",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserAvatar;

pub type User = get_user_avatar::GetUserAvatarUser;

pub struct Avatar {
    common: CommonComponentParts<Self>,
    /// The user info. If none, the error is in `error`. If `error` is None, then we haven't
    /// received the server response yet.
    avatar: Option<String>,
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the user details response, either the user data or an error.
    UserAvatarResponse(Result<get_user_avatar::ResponseData>),
    Update
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub username: String,
    pub width: i32,
    pub height: i32,
}

impl CommonComponent<Avatar> for Avatar {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::UserAvatarResponse(response) => match response {
                Ok(user) => self.avatar = user.user.avatar,
                Err(e) => {
                    self.avatar = None;
                    bail!("Error getting user details: {}", e);
                }
            },
            Msg::Update => self.get_user_avatar(),
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Avatar {
    fn get_user_avatar(&mut self) {
        if self.common.username.len() > 0 {
            self.common.call_graphql::<GetUserAvatar, _>(
                get_user_avatar::Variables {
                    id: self.common.username.clone(),
                },
                Msg::UserAvatarResponse,
                "Error trying to fetch user avatar",
            )
        }
    }
}

impl Component for Avatar {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut avatar = Self {
            common: CommonComponentParts::<Self>::create(props, link),
            avatar: None,
        };
        avatar.get_user_avatar();
        avatar
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        match &self.avatar {
            Some(avatar) => html! {
                <img
                        id="avatarDisplay"
                        src={format!("data:image/jpeg;base64, {}", avatar)}
                        style={format!("max-height:{}px;max-width:{}px;height:auto;width:auto;", self.common.props.height,self.common.props.width)}
                        alt="Avatar" />
            },
            None => html! {
                <svg xmlns="http://www.w3.org/2000/svg"
                      width={self.common.props.width.to_string()}
                      height={self.common.props.height.to_string()}
                      fill="currentColor"
                      class="bi bi-person-circle"
                      viewBox="0 0 16 16">
                      <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
                      <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
                    </svg>
            },
        }
    }
}
