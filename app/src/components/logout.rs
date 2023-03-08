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
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool> {
        match msg {
            Msg::LogoutRequested => {
                self.common
                    .call_backend(HostService::logout, (), Msg::LogoutCompleted)?;
            }
            Msg::LogoutCompleted(res) => {
                res?;
                delete_cookie("user_id")?;
                self.common.on_logged_out.emit(());
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

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        LogoutButton {
            common: CommonComponentParts::<Self>::create(props, link),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        CommonComponentParts::<Self>::update(self, msg)
    }

    fn change(&mut self, props: Self::Properties) -> ShouldRender {
        self.common.change(props)
    }

    fn view(&self) -> Html {
        let link = &self.common;
        html! {
            <button
              class="dropdown-item"
              onclick={link.callback(|_| Msg::LogoutRequested)}>
              {"Logout"}
            </button>
        }
    }
}
