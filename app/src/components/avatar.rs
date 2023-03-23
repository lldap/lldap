use crate::{
    components::avatar_event_bus::{AvatarEventBus, Response},
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{bail, Result};
use graphql_client::GraphQLQuery;
use serde::{Deserialize, Serialize};
use yew::prelude::*;
use yew_agent::{Bridge, Bridged};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_avatar.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserAvatar;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AvatarData(String);

impl AvatarData {
    pub fn new(data: String) -> Self {
        AvatarData(data)
    }
}

pub struct Avatar {
    common: CommonComponentParts<Self>,
    avatar: Option<AvatarData>,
    _producer: Box<dyn Bridge<AvatarEventBus>>,
}

/// State machine describing the possible transitions of the component state.
/// It starts out by fetching the user's details from the backend when loading.
pub enum Msg {
    /// Received the user details response, either the user data or an error.
    UserAvatarResponse(Result<get_user_avatar::ResponseData>),
    Update(Response),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub username: String,
    pub width: i32,
    pub height: i32,
}

impl CommonComponent<Avatar> for Avatar {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::UserAvatarResponse(response) => match response {
                Ok(user) => self.avatar = user.user.avatar.map(AvatarData::new),
                Err(e) => {
                    self.avatar = None;
                    bail!("Error getting user avatar: {}", e);
                }
            },
            Msg::Update(Response::Update((username, avatar))) => {
                if username == ctx.props().username {
                    self.avatar = avatar;
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Avatar {
    fn get_user_avatar(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetUserAvatar, _>(
            ctx,
            get_user_avatar::Variables {
                id: ctx.props().username.clone(),
            },
            Msg::UserAvatarResponse,
            "Error trying to fetch user avatar",
        )
    }
}

impl Component for Avatar {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut avatar = Self {
            common: CommonComponentParts::<Self>::create(),
            avatar: None,
            _producer: AvatarEventBus::bridge(ctx.link().callback(Msg::Update)),
        };
        avatar.get_user_avatar(ctx);
        avatar
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.avatar {
            Some(avatar) => html! {
                <img
                        class="avatar"
                        src={format!("data:image/jpeg;base64, {}", avatar.0)}
                        style={format!("max-height:{}px;max-width:{}px;height:auto;width:auto;", ctx.props().height,ctx.props().width)}
                        alt="Avatar" />
            },
            None => html! {
                <svg xmlns="http://www.w3.org/2000/svg"
                      width={ctx.props().width.to_string()}
                      height={ctx.props().height.to_string()}
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
