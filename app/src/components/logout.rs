use crate::infra::{api::HostService, cookies::delete_cookie};
use anyhow::Result;
use yew::prelude::*;
use yew::services::{fetch::FetchTask, ConsoleService};

pub struct LogoutButton {
    link: ComponentLink<Self>,
    on_logged_out: Callback<()>,
    // Used to keep the request alive long enough.
    _task: Option<FetchTask>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_out: Callback<()>,
}

pub enum Msg {
    LogoutRequested,
    LogoutCompleted(Result<()>),
}

impl Component for LogoutButton {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        LogoutButton {
            link,
            on_logged_out: props.on_logged_out,
            _task: None,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::LogoutRequested => {
                match HostService::logout(self.link.callback(Msg::LogoutCompleted)) {
                    Ok(task) => self._task = Some(task),
                    Err(e) => ConsoleService::error(&e.to_string()),
                };
                false
            }
            Msg::LogoutCompleted(res) => {
                if let Err(e) = res {
                    ConsoleService::error(&e.to_string());
                }
                match delete_cookie("user_id") {
                    Err(e) => {
                        ConsoleService::error(&e.to_string());
                        false
                    }
                    Ok(()) => {
                        self.on_logged_out.emit(());
                        true
                    }
                }
            }
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <button onclick=self.link.callback(|_| { Msg::LogoutRequested })>{"Logout"}</button>
        }
    }
}
