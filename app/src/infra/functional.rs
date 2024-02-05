use crate::infra::api::HostService;
use anyhow::Result;
use graphql_client::GraphQLQuery;
use wasm_bindgen_futures::spawn_local;
use yew::{use_effect, use_state, UseStateHandle};

// Enum to represent a result that is fetched asynchronously.
#[derive(Debug)]
pub enum LoadableResult<T> {
    // The result is still being fetched
    Loading,
    // The async call is completed
    Loaded(Result<T>),
}

pub fn use_graphql_call<QueryType>(
    variables: QueryType::Variables,
) -> UseStateHandle<LoadableResult<QueryType::ResponseData>>
where
    QueryType: GraphQLQuery + 'static,
{
    let loadable_result: UseStateHandle<LoadableResult<QueryType::ResponseData>> =
        use_state(|| LoadableResult::Loading);
    {
        let loadable_result = loadable_result.clone();
        use_effect(move || {
            let task = HostService::graphql_query::<QueryType>(variables, "Failed graphql query");

            spawn_local(async move {
                let response = task.await;
                loadable_result.set(LoadableResult::Loaded(response));
            });

            || ()
        })
    }
    loadable_result.clone()
}
