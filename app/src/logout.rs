use crate::cookies::delete_cookie;
use yew::prelude::*;
use yew::services::ConsoleService;

pub struct LogoutButton {
    link: ComponentLink<Self>,
    on_logged_out: Callback<()>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub on_logged_out: Callback<()>,
}

pub enum Msg {
    Logout,
}

impl Component for LogoutButton {
    type Message = Msg;
    type Properties = Props;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        LogoutButton {
            link: link.clone(),
            on_logged_out: props.on_logged_out,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Logout => match delete_cookie("user_id") {
                Err(e) => {
                    ConsoleService::error(&e.to_string());
                    false
                }
                Ok(()) => {
                    self.on_logged_out.emit(());
                    true
                }
            },
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html! {
            <button onclick=self.link.callback(|_| { Msg::Logout })>{"Logout"}</button>
        }
    }
}
