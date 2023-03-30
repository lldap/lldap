use crate::infra::api::HostService;
use anyhow::Result;
use gloo_console::error;
use graphql_client::GraphQLQuery;
use std::{collections::HashMap, rc::Rc};
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_avatar.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetUserAvatar;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_users.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq,Hash",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUserNames;

#[derive(Debug, PartialEq, Clone)]
pub enum CacheAction {
    Clear,
    AddAvatar((String, Option<String>)),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AvatarCache {
    pub avatars: HashMap<String, Option<String>>,
}

impl Reducible for AvatarCache {
    type Action = CacheAction;

    fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
        match action {
            CacheAction::AddAvatar((username, avatar)) => {
                let mut avatars = self.avatars.clone();
                avatars.insert(username, avatar);
                AvatarCache { avatars }.into()
            }
            CacheAction::Clear => AvatarCache {
                avatars: HashMap::new(),
            }
            .into(),
        }
    }
}

pub type AvatarCacheContext = UseReducerHandle<AvatarCache>;

#[derive(Debug, PartialEq, Clone)]
pub enum CacheMode {
    AllUsers,
    SingleUser(String),
    None,
}

#[derive(Properties, Debug, PartialEq)]
pub struct AvatarCacheProviderProps {
    #[prop_or_default]
    pub children: Children,

    pub mode: CacheMode,
}

#[function_component(AvatarCacheProvider)]
pub fn avatar_cache_provider(props: &AvatarCacheProviderProps) -> Html {
    let cache = use_reducer(|| AvatarCache {
        avatars: HashMap::new(),
    });
    {
        let cache = cache.clone();
        let mode = props.mode.clone();
        use_effect_with_deps(
            move |mode| {
                match mode {
                    CacheMode::None => {
                        cache.dispatch(CacheAction::Clear)
                    }
                    CacheMode::AllUsers => {
                        let cache = cache.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            let result = fetch_all_avatars(cache).await;
                            if let Err(e) = result {
                                error!(&format!("Could not fetch all avatars: {e:#}"))
                            }
                        });
                    }
                    CacheMode::SingleUser(username) => {
                        let cache = cache.clone();
                        let username = username.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            let result = HostService::graphql_query::<GetUserAvatar>(
                                get_user_avatar::Variables { id: username },
                                "Error trying to fetch user avatar",
                            )
                            .await;
                            if let Ok(response) = result {
                                cache.dispatch(CacheAction::AddAvatar((
                                    response.user.id,
                                    response.user.avatar,
                                )))
                            }
                        });
                    }
                };
                move || cache.dispatch(CacheAction::Clear)
            },
            mode,
        )
    }

    html! {
        <ContextProvider<AvatarCacheContext> context={cache}>
            {props.children.clone()}
        </ContextProvider<AvatarCacheContext>>
    }
}

async fn fetch_all_avatars(cache: UseReducerHandle<AvatarCache>) -> Result<()> {
    let response = HostService::graphql_query::<ListUserNames>(
        list_user_names::Variables { filters: None },
        "Error trying to fetch user list",
    )
    .await?;
    for user in &response.users {
        let result = HostService::graphql_query::<GetUserAvatar>(
            get_user_avatar::Variables {
                id: user.id.clone(),
            },
            "Error trying to fetch user avatar",
        )
        .await;
        if let Ok(response) = result {
            cache.dispatch(CacheAction::AddAvatar((
                response.user.id,
                response.user.avatar,
            )));
        }
    }

    return Ok(());
}
