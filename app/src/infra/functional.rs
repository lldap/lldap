use crate::infra::api::HostService;
use anyhow::Result;
use graphql_client::GraphQLQuery;
use wasm_bindgen_futures::spawn_local;
use yew::{UseStateHandle, use_effect_with_deps, use_state_eq};

// Enum to represent a result that is fetched asynchronously.
#[derive(Debug)]
pub enum LoadableResult<T> {
    // The result is still being fetched
    Loading,
    // The async call is completed
    Loaded(Result<T>),
}

impl<T: PartialEq> PartialEq for LoadableResult<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LoadableResult::Loading, LoadableResult::Loading) => true,
            (LoadableResult::Loaded(Ok(d1)), LoadableResult::Loaded(Ok(d2))) => d1.eq(d2),
            (LoadableResult::Loaded(Err(e1)), LoadableResult::Loaded(Err(e2))) => {
                e1.to_string().eq(&e2.to_string())
            }
            _ => false,
        }
    }
}

pub fn use_graphql_call<QueryType>(
    variables: QueryType::Variables,
) -> UseStateHandle<LoadableResult<QueryType::ResponseData>>
where
    QueryType: GraphQLQuery + 'static,
    <QueryType as graphql_client::GraphQLQuery>::Variables: std::cmp::PartialEq + Clone,
    <QueryType as graphql_client::GraphQLQuery>::ResponseData: std::cmp::PartialEq,
{
    let loadable_result: UseStateHandle<LoadableResult<QueryType::ResponseData>> =
        use_state_eq(|| LoadableResult::Loading);
    {
        let loadable_result = loadable_result.clone();
        use_effect_with_deps(
            move |variables| {
                let task = HostService::graphql_query::<QueryType>(
                    variables.clone(),
                    "Failed graphql query",
                );

                spawn_local(async move {
                    let response = task.await;
                    loadable_result.set(LoadableResult::Loaded(response));
                });

                || ()
            },
            variables,
        )
    }
    loadable_result.clone()
}
