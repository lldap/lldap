use async_trait::async_trait;
use ldap3_proto::{
    proto::{LdapBindRequest, LdapExtendedRequest, LdapModifyRequest, LdapOp, LdapSearchRequest},
    LdapSearchResultEntry,
};
use lldap_domain::{
    requests::{CreateGroupRequest, CreateUserRequest, UpdateGroupRequest, UpdateUserRequest},
    types::{GroupId, UserId},
};
use lldap_key_value_store::api::store::KeyValueStore;
use lldap_plugin_kv_store::store::ScopeAndKey;

use crate::{
    api::{
        arguments::ldap_search_result::SearchResult,
        backend::BackendAPI,
        types::{PluginConfig, PluginContext},
    },
    internal::{plugins, types::plugins::PluginRegistry},
};

use super::arguments::ldap_bind_result::BindResult;

#[async_trait]
pub trait PluginHandlerEvents {
    async fn initialize_plugins<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
    ) -> Result<(), String>;

    async fn on_create_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateUserRequest,
    ) -> Result<CreateUserRequest, String>;

    async fn on_created_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateUserRequest,
    ) -> Result<(), String>;

    async fn on_update_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateUserRequest,
    ) -> Result<UpdateUserRequest, String>;

    async fn on_updated_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateUserRequest,
    ) -> Result<(), String>;

    async fn on_delete_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
    ) -> Result<UserId, String>;

    async fn on_deleted_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
    ) -> Result<(), String>;

    async fn on_create_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateGroupRequest,
    ) -> Result<CreateGroupRequest, String>;

    async fn on_created_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateGroupRequest,
    ) -> Result<(), String>;

    async fn on_update_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateGroupRequest,
    ) -> Result<UpdateGroupRequest, String>;

    async fn on_updated_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateGroupRequest,
    ) -> Result<(), String>;

    async fn on_delete_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        group_id: GroupId,
    ) -> Result<GroupId, String>;

    async fn on_deleted_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        group_id: GroupId,
    ) -> Result<(), String>;

    async fn on_added_user_to_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), String>;

    async fn on_removed_user_from_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), String>;

    async fn on_ldap_bind<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        bind_request: LdapBindRequest,
        bind_result: BindResult,
    ) -> Result<BindResult, String>;

    async fn on_ldap_unbind<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
    ) -> Result<(), String>;

    async fn on_ldap_modify<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        modify_request: LdapModifyRequest,
        modify_result: Vec<LdapOp>,
    ) -> Result<Vec<LdapOp>, String>;

    async fn on_ldap_extended_request<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        request: LdapExtendedRequest,
        result: Vec<LdapOp>,
    ) -> Result<Vec<LdapOp>, String>;

    async fn on_ldap_password_update<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
        password: String,
    ) -> Result<(), String>;

    async fn on_ldap_search_result<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        search_request: LdapSearchRequest,
        search_result: SearchResult,
    ) -> Result<SearchResult, String>;

    async fn on_ldap_root_dse<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        search_result_entry: LdapSearchResultEntry,
    ) -> Result<LdapSearchResultEntry, String>;
}

#[derive(Clone, Debug)]
pub struct PluginHandler<KVStore: KeyValueStore<ScopeAndKey> + 'static> {
    pub(crate) plugin_registry: PluginRegistry,
    pub(crate) kvstore: KVStore,
}

pub struct PluginLoader;

impl PluginLoader {
    pub fn from<KVStore: KeyValueStore<ScopeAndKey> + 'static>(
        plugins: Vec<PluginConfig>,
        kvstore: KVStore,
    ) -> PluginHandler<KVStore> {
        let plugins = plugins::load_plugins(plugins);
        PluginHandler {
            plugin_registry: plugins,
            kvstore,
        }
    }
}
