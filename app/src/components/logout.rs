use crate::infra::{
    api::HostService,
    common_component::{CommonComponent, CommonComponentParts},
    cookies::delete_cookie,
};
use anyhow::Result;
use yew::prelude::*;

pub struct LogoutButton {
    common: CommonComponentParts<Self>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_out: Callback<()>,
}

pub enum Msg {
    LogoutRequested,
    LogoutCompleted(Result<()>),
}

impl CommonComponent<LogoutButton> for LogoutButton {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::LogoutRequested => {
                self.common
                    .call_backend(ctx, HostService::logout(), Msg::LogoutCompleted);
            }
            Msg::LogoutCompleted(res) => {
                res?;
                delete_cookie("user_id")?;
                ctx.props().on_logged_out.emit(());
            }
        }
        Ok(false)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for LogoutButton {
    type Message = Msg;
    type Properties = Props;

    fn create(_: &Context<Self>) -> Self {
        LogoutButton {
            common: CommonComponentParts::<Self>::create(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = &ctx.link();
        html! {
            <button
              class="dropdown-item"
              onclick={link.callback(|_| Msg::LogoutRequested)}>
              {"Logout"}
            </button>
        }
    }
}
