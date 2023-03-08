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

use std::{
    future::Future,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use crate::infra::api::HostService;
use anyhow::{Error, Result};
use gloo_console::error;
use graphql_client::GraphQLQuery;
use yew::prelude::*;

/// Trait required for common components.
pub trait CommonComponent<C: Component + CommonComponent<C>>: Component {
    /// Handle the incoming message. If an error is returned here, any running task will be
    /// cancelled, the error will be written to the [`CommonComponentParts::error`] and the
    /// component will be refreshed.
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool>;
    /// Get a mutable reference to the inner component parts, necessary for the CRTP.
    fn mut_common(&mut self) -> &mut CommonComponentParts<C>;
}

/// Structure that contains the common parts needed by most components.
/// The fields of [`props`] are directly accessible through a `Deref` implementation.
pub struct CommonComponentParts<C: CommonComponent<C>> {
    pub error: Option<Error>,
    is_task_running: Arc<Mutex<bool>>,
    _phantom: PhantomData<C>,
}

impl<C: CommonComponent<C>> CommonComponentParts<C> {
    pub fn create() -> Self {
        CommonComponentParts {
            error: None,
            is_task_running: Arc::new(Mutex::new(false)),
            _phantom: PhantomData::<C>,
        }
    }
    /// Whether there is a currently running task in the background.
    pub fn is_task_running(&self) -> bool {
        *self.is_task_running.lock().unwrap()
    }

    /// This should be called from the [`yew::prelude::Component::update`]: it will in turn call
    /// [`CommonComponent::handle_msg`] and handle any resulting error.
    pub fn update(com: &mut C, ctx: &Context<C>, msg: <C as Component>::Message) -> bool {
        com.mut_common().error = None;
        match com.handle_msg(ctx, msg) {
            Err(e) => {
                error!(&e.to_string());
                com.mut_common().error = Some(e);
                assert!(!*com.mut_common().is_task_running.lock().unwrap());
                true
            }
            Ok(b) => b,
        }
    }

    /// Same as above, but the resulting error is instead passed to the reporting function.
    pub fn update_and_report_error(
        com: &mut C,
        ctx: &Context<C>,
        msg: <C as Component>::Message,
        report_fn: Callback<Error>,
    ) -> bool {
        let should_render = Self::update(com, ctx, msg);
        com.mut_common()
            .error
            .take()
            .map(|e| {
                report_fn.emit(e);
                true
            })
            .unwrap_or(should_render)
    }

    /// Call `method` from the backend with the given `request`, and pass the `callback` for the
    /// result. Returns whether _starting the call_ failed.
    pub fn call_backend<Fut, Cb, Resp>(&mut self, ctx: &Context<C>, fut: Fut, callback: Cb)
    where
        Fut: Future<Output = Resp> + 'static,
        Cb: FnOnce(Resp) -> <C as Component>::Message + 'static,
    {
        {
            let mut running = self.is_task_running.lock().unwrap();
            assert!(!*running);
            *running = true;
        }
        let is_task_running = self.is_task_running.clone();
        ctx.link().send_future(async move {
            let res = fut.await;
            *is_task_running.lock().unwrap() = false;
            callback(res)
        });
    }

    /// Call the backend with a GraphQL query.
    ///
    /// `EnumCallback` should usually be left as `_`.
    pub fn call_graphql<QueryType, EnumCallback>(
        &mut self,
        ctx: &Context<C>,
        variables: QueryType::Variables,
        enum_callback: EnumCallback,
        error_message: &'static str,
    ) where
        QueryType: GraphQLQuery + 'static,
        EnumCallback: Fn(Result<QueryType::ResponseData>) -> <C as Component>::Message + 'static,
    {
        {
            let mut running = self.is_task_running.lock().unwrap();
            assert!(!*running);
            *running = true;
        }
        let is_task_running = self.is_task_running.clone();
        ctx.link().send_future(async move {
            let res = HostService::graphql_query::<QueryType>(variables, error_message).await;
            *is_task_running.lock().unwrap() = false;
            enum_callback(res)
        });
    }

    /*
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
    */
}
