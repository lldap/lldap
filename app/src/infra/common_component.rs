use crate::infra::api::HostService;
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::{
    prelude::*,
    services::{fetch::FetchTask, ConsoleService},
};
use yewtil::NeqAssign;

pub trait CommonComponent<C: Component + CommonComponent<C>>: Component {
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool>;
    fn mut_common(&mut self) -> &mut CommonComponentParts<C>;
}

pub struct CommonComponentParts<C: CommonComponent<C>> {
    link: ComponentLink<C>,
    pub props: <C as Component>::Properties,
    pub error: Option<Error>,
    task: Option<FetchTask>,
}

impl<C: CommonComponent<C>> CommonComponentParts<C> {
    pub fn is_task_running(&self) -> bool {
        self.task.is_some()
    }

    pub fn cancel_task(&mut self) {
        self.task = None;
    }

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
                com.mut_common().cancel_task();
                true
            }
            Ok(b) => b,
        }
    }

    pub fn update_and_report_error(
        com: &mut C,
        msg: <C as Component>::Message,
        report_fn: Callback<Error>,
    ) -> ShouldRender {
        let should_render = Self::update(com, msg);
        com.mut_common()
            .error
            .take()
            .map(|e| {
                report_fn.emit(e);
                true
            })
            .unwrap_or(should_render)
    }

    pub fn change(&mut self, props: <C as Component>::Properties) -> ShouldRender
    where
        <C as yew::Component>::Properties: std::cmp::PartialEq,
    {
        self.props.neq_assign(props)
    }

    pub fn callback<F, IN, M>(&self, function: F) -> Callback<IN>
    where
        M: Into<C::Message>,
        F: Fn(IN) -> M + 'static,
    {
        self.link.callback(function)
    }

    pub fn call_backend<M, Req, Cb, Resp>(
        &mut self,
        method: M,
        req: Req,
        callback: Cb,
    ) -> Result<()>
    where
        M: Fn(Req, Callback<Resp>) -> Result<FetchTask>,
        Cb: FnOnce(Resp) -> <C as Component>::Message + 'static,
    {
        self.task = Some(method(req, self.link.callback_once(callback))?);
        Ok(())
    }

    pub fn call_graphql<QueryType, EnumCallback>(
        &mut self,
        variables: QueryType::Variables,
        enum_callback: EnumCallback,
        error_message: &'static str,
    ) where
        QueryType: GraphQLQuery + 'static,
        EnumCallback: Fn(Result<QueryType::ResponseData>) -> <C as Component>::Message + 'static,
    {
        self.task = HostService::graphql_query::<QueryType>(
            variables,
            self.link.callback(enum_callback),
            error_message,
        )
        .map_err::<(), _>(|e| {
            ConsoleService::log(&e.to_string());
            self.error = Some(e);
        })
        .ok();
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
