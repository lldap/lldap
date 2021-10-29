use anyhow::{Error, Result};
use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};

pub trait CommonComponent<C: Component + CommonComponent<C>>: Component {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool>;
    fn mut_common(&mut self) -> &mut CommonComponentParts<C>;
}

pub struct CommonComponentParts<C: CommonComponent<C>> {
    pub link: ComponentLink<C>,
    pub props: <C as Component>::Properties,
    pub error: Option<Error>,
    pub task: Option<FetchTask>,
}

impl<C: CommonComponent<C>> CommonComponentParts<C> {
    pub fn create(props: <C as Component>::Properties, link: ComponentLink<C>) -> Self {
        Self {
            link,
            props,
            error: None,
            task: None,
        }
    }

    pub fn update(com: &mut C, msg: <C as Component>::Message) -> ShouldRender {
        com.mut_common().error = None;
        match com.handle_msg(msg) {
            Err(e) => {
                ConsoleService::error(&e.to_string());
                com.mut_common().error = Some(e);
                true
            }
            Ok(b) => b,
        }
    }

    pub fn call_backend<M, Req, Cb, Resp>(
        &mut self,
        method: M,
        req: Req,
        callback: Cb,
    ) -> Result<()>
    where
        M: Fn(Req, Callback<Resp>) -> Result<FetchTask>,
        Cb: Fn(Resp) -> <C as Component>::Message + 'static,
    {
        self.task = Some(method(req, self.link.callback(callback))?);
        Ok(())
    }
}

impl<C: Component + CommonComponent<C>> std::ops::Deref for CommonComponentParts<C> {
    type Target = <C as Component>::Properties;

    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        &self.props
    }
}

impl<C: Component + CommonComponent<C>> std::ops::DerefMut for CommonComponentParts<C> {
    fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
        &mut self.props
    }
}
