//! Common Component module.
//! This is used to factor out some common functionality that is recurrent in modules all over the
//! application. In particular:
//!   - error handling
//!   - task handling
//!   - storing props
//!
//! The pattern used is the
//! [CRTP](https://en.wikipedia.org/wiki/Curiously_recurring_template_pattern) pattern: The
//! [`CommonComponent`] trait must be implemented with `Self` as the parameter, e.g.
//!
//! ```ignore
//! struct MyComponent;
//! impl CommonComponent<MyComponent> for MyComponent { ... }
//! ```
//!
//! The component should also have a `CommonComponentParts<Self>` as a field, usually named
//! `common`.
//!
//! Then the [`yew::prelude::Component::update`] method can delegate to
//! [`CommonComponentParts::update`]. This will in turn call [`CommonComponent::handle_msg`] and
//! take care of error and task handling.

use crate::infra::api::HostService;
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use yew::{
    prelude::*,
    services::{
        fetch::FetchTask,
        reader::{FileData, ReaderService, ReaderTask},
        ConsoleService,
    },
};
use yewtil::NeqAssign;

/// Trait required for common components.
pub trait CommonComponent<C: Component + CommonComponent<C>>: Component {
    /// Handle the incoming message. If an error is returned here, any running task will be
    /// cancelled, the error will be written to the [`CommonComponentParts::error`] and the
    /// component will be refreshed.
    fn handle_msg(&mut self, msg: <Self as Component>::Message) -> Result<bool>;
    /// Get a mutable reference to the inner component parts, necessary for the CRTP.
    fn mut_common(&mut self) -> &mut CommonComponentParts<C>;
}

enum AnyTask {
    None,
    FetchTask(FetchTask),
    ReaderTask(ReaderTask),
}

impl AnyTask {
    fn is_some(&self) -> bool {
        !matches!(self, AnyTask::None)
    }
}

impl From<Option<FetchTask>> for AnyTask {
    fn from(task: Option<FetchTask>) -> Self {
        match task {
            Some(t) => AnyTask::FetchTask(t),
            None => AnyTask::None,
        }
    }
}

/// Structure that contains the common parts needed by most components.
/// The fields of [`props`] are directly accessible through a `Deref` implementation.
pub struct CommonComponentParts<C: CommonComponent<C>> {
    link: ComponentLink<C>,
    pub props: <C as Component>::Properties,
    pub error: Option<Error>,
    task: AnyTask,
}

impl<C: CommonComponent<C>> CommonComponentParts<C> {
    /// Whether there is a currently running task in the background.
    pub fn is_task_running(&self) -> bool {
        self.task.is_some()
    }

    /// Cancel any background task.
    pub fn cancel_task(&mut self) {
        self.task = AnyTask::None;
    }

    pub fn create(props: <C as Component>::Properties, link: ComponentLink<C>) -> Self {
        Self {
            link,
            props,
            error: None,
            task: AnyTask::None,
        }
    }

    /// This should be called from the [`yew::prelude::Component::update`]: it will in turn call
    /// [`CommonComponent::handle_msg`] and handle any resulting error.
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

    /// Same as above, but the resulting error is instead passed to the reporting function.
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

    /// This can be called from [`yew::prelude::Component::update`]: it will check if the
    /// properties have changed and return whether the component should update.
    pub fn change(&mut self, props: <C as Component>::Properties) -> ShouldRender
    where
        <C as yew::Component>::Properties: std::cmp::PartialEq,
    {
        self.props.neq_assign(props)
    }

    /// Create a callback from the link.
    pub fn callback<F, IN, M>(&self, function: F) -> Callback<IN>
    where
        M: Into<C::Message>,
        F: Fn(IN) -> M + 'static,
    {
        self.link.callback(function)
    }

    /// Call `method` from the backend with the given `request`, and pass the `callback` for the
    /// result. Returns whether _starting the call_ failed.
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
        self.task = AnyTask::FetchTask(method(req, self.link.callback_once(callback))?);
        Ok(())
    }

    /// Call the backend with a GraphQL query.
    ///
    /// `EnumCallback` should usually be left as `_`.
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
        .ok()
        .into();
    }

    pub(crate) fn read_file<Cb>(&mut self, file: web_sys::File, callback: Cb) -> Result<()>
    where
        Cb: FnOnce(FileData) -> <C as Component>::Message + 'static,
    {
        self.task = AnyTask::ReaderTask(ReaderService::read_file(
            file,
            self.link.callback_once(callback),
        )?);
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
