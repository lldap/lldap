use std::collections::HashSet;

use async_trait::async_trait;
use chrono::NaiveDateTime;
use ldap3_proto::{
    proto::{LdapBindRequest, LdapExtendedRequest, LdapModifyRequest, LdapOp, LdapSearchRequest},
    LdapSearchResultEntry,
};
use lldap_auth::{login, registration, types::UserId};
use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    schema::Schema,
    types::{AttributeName, Group, GroupDetails, GroupId, LdapObjectClass, User, UserAndGroups},
};
use lldap_domain_handlers::handler::{
    BackendHandler, BindRequest, GroupBackendHandler, GroupListerBackendHandler,
    GroupRequestFilter, LoginHandler, ReadSchemaBackendHandler, RequestContext,
    SchemaBackendHandler, UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
    WithContextHandler,
};
use lldap_domain_model::error::Result;
use lldap_plugin_engine::api::{
    arguments::{ldap_bind_result::BindResult, ldap_search_result::SearchResult},
    handler::{PluginHandler, PluginHandlerEvents},
    types::PluginContext,
};
use lldap_plugin_kv_store::store::PluginKeyValueStore;

use crate::{
    domain::{
        ldap::utils::LdapInfo, opaque_handler::OpaqueHandler, plugin::backend::ServerBackendAPI,
        sql_backend_handler::SqlBackendHandler,
    },
    infra::{ldap_handler::InternalSearchResults, tcp_backend_handler::TcpBackendHandler},
};

use tracing::instrument;

#[derive(Clone, Debug)]
pub struct PluginBackendHandler {
    pub(crate) backend_handler: SqlBackendHandler,
    pub(crate) backend_api: &'static ServerBackendAPI<SqlBackendHandler>,
    pub(crate) plugin_handler: PluginHandler<PluginKeyValueStore>,
    pub(crate) request_context: RequestContext,
}

impl PluginBackendHandler {
    pub fn new(
        backend_handler: &SqlBackendHandler,
        plugin_handler: PluginHandler<PluginKeyValueStore>,
    ) -> Self {
        let api: &'static ServerBackendAPI<SqlBackendHandler> =
            Box::leak(Box::new(ServerBackendAPI {
                backend_handler: backend_handler.clone(),
                ldap_info: LdapInfo::from(
                    backend_handler.config.ldap_base_dn.clone(),
                    backend_handler.config.ignored_user_attributes.clone(),
                    backend_handler.config.ignored_group_attributes.clone(),
                ),
            }));
        PluginBackendHandler {
            backend_handler: backend_handler.clone(),
            backend_api: api,
            plugin_handler: plugin_handler,
            request_context: RequestContext::empty(),
        }
    }
    pub fn new_plugin_context(&self) -> PluginContext<ServerBackendAPI<SqlBackendHandler>> {
        PluginContext::new(
            self.backend_api,
            self.request_context.validation_results.clone(),
        )
    }
    pub async fn initialize_plugins(&self) -> std::result::Result<(), String> {
        let ctx = self.new_plugin_context();
        self.plugin_handler.initialize_plugins(ctx).await
    }
}

#[async_trait]
impl BackendHandler for PluginBackendHandler {}

impl WithContextHandler for PluginBackendHandler {
    fn with_context(&self, context: RequestContext) -> Self {
        PluginBackendHandler {
            backend_handler: self.backend_handler.clone(),
            backend_api: self.backend_api,
            plugin_handler: self.plugin_handler.clone(),
            request_context: context,
        }
    }
}

#[async_trait]
impl ReadSchemaBackendHandler for PluginBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn get_schema(&self) -> Result<Schema> {
        self.backend_handler.get_schema().await
    }
}

#[async_trait]
impl SchemaBackendHandler for PluginBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        self.backend_handler.add_user_attribute(request).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        self.backend_handler.add_group_attribute(request).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()> {
        self.backend_handler.delete_user_attribute(name).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()> {
        self.backend_handler.delete_group_attribute(name).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        self.backend_handler.add_user_object_class(name).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        self.backend_handler.add_group_object_class(name).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        self.backend_handler.delete_user_object_class(name).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        self.backend_handler.delete_group_object_class(name).await
    }
}

#[async_trait]
impl GroupBackendHandler for PluginBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails> {
        self.backend_handler.get_group_details(group_id).await
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        let ctx = self.new_plugin_context();
        let request = self
            .plugin_handler
            .on_update_group(ctx.clone(), request.clone())
            .await
            .unwrap_or(request);
        self.backend_handler.update_group(request.clone()).await?;
        let _ = self.plugin_handler.on_updated_group(ctx, request).await;
        Ok(())
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId> {
        let ctx = self.new_plugin_context();
        let request = self
            .plugin_handler
            .on_create_group(ctx.clone(), request.clone())
            .await
            .unwrap_or(request);
        let group_id = self.backend_handler.create_group(request.clone()).await?;
        let _ = self.plugin_handler.on_created_group(ctx, request).await;
        Ok(group_id)
    }
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        let ctx = self.new_plugin_context();
        let group_id = self
            .plugin_handler
            .on_delete_group(ctx.clone(), group_id.clone())
            .await
            .unwrap_or(group_id);
        self.backend_handler.delete_group(group_id.clone()).await?;
        let _ = self.plugin_handler.on_deleted_group(ctx, group_id).await;
        Ok(())
    }
}

#[async_trait]
impl GroupListerBackendHandler for PluginBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        self.backend_handler.list_groups(filters).await
    }
}

#[async_trait]
impl UserBackendHandler for PluginBackendHandler {
    #[instrument(skip_all, level = "debug", ret, fields(user_id = ?user_id.as_str()))]
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        self.backend_handler.get_user_details(user_id).await
    }
    #[instrument(skip(self), level = "debug", err, fields(user_id = ?request.user_id.as_str()))]
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        let ctx = self.new_plugin_context();
        let request = self
            .plugin_handler
            .on_create_user(ctx.clone(), request.clone())
            .await
            .unwrap_or(request);
        self.backend_handler.create_user(request.clone()).await?;
        let _ = self.plugin_handler.on_created_user(ctx, request).await;
        Ok(())
    }
    #[instrument(skip(self), level = "debug", err, fields(user_id = ?request.user_id.as_str()))]
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        let ctx = self.new_plugin_context();
        let request = self
            .plugin_handler
            .on_update_user(ctx.clone(), request.clone())
            .await
            .unwrap_or(request);
        self.backend_handler.update_user(request.clone()).await?;
        let _ = self.plugin_handler.on_updated_user(ctx, request).await;
        Ok(())
    }
    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        let ctx = self.new_plugin_context();
        let user_id = self
            .plugin_handler
            .on_delete_user(ctx.clone(), user_id.clone())
            .await
            .unwrap_or(user_id.clone());
        self.backend_handler.delete_user(&user_id).await?;
        let _ = self.plugin_handler.on_deleted_user(ctx, user_id).await;
        Ok(())
    }
    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        self.backend_handler
            .add_user_to_group(user_id, group_id.clone())
            .await?;
        let ctx = self.new_plugin_context();
        let _ = self
            .plugin_handler
            .on_added_user_to_group(ctx, user_id.clone(), group_id)
            .await;
        Ok(())
    }
    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        self.backend_handler
            .remove_user_from_group(user_id, group_id)
            .await?;
        let ctx = self.new_plugin_context();
        let _ = self
            .plugin_handler
            .on_removed_user_from_group(ctx, user_id.clone(), group_id)
            .await;
        Ok(())
    }
    #[instrument(skip_all, level = "debug", ret, fields(user_id = ?user_id.as_str()))]
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        self.backend_handler.get_user_groups(user_id).await
    }
}

#[async_trait]
impl UserListerBackendHandler for PluginBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        self.backend_handler.list_users(filters, get_groups).await
    }
}

#[async_trait]
impl LoginHandler for PluginBackendHandler {
    async fn bind(&self, request: BindRequest) -> Result<()> {
        self.backend_handler.bind(request).await
    }
}

#[async_trait]
impl OpaqueHandler for PluginBackendHandler {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse> {
        self.backend_handler.login_start(request).await
    }
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId> {
        self.backend_handler.login_finish(request).await
    }
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        self.backend_handler.registration_start(request).await
    }
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()> {
        self.backend_handler.registration_finish(request).await
    }
}

#[async_trait]
impl TcpBackendHandler for PluginBackendHandler {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>> {
        self.backend_handler.get_jwt_blacklist().await
    }
    async fn create_refresh_token(&self, user: &UserId) -> Result<(String, chrono::Duration)> {
        self.backend_handler.create_refresh_token(user).await
    }
    async fn register_jwt(
        &self,
        user: &UserId,
        jwt_hash: u64,
        expiry_date: NaiveDateTime,
    ) -> Result<()> {
        self.backend_handler
            .register_jwt(user, jwt_hash, expiry_date)
            .await
    }
    async fn check_token(&self, refresh_token_hash: u64, user: &UserId) -> Result<bool> {
        self.backend_handler
            .check_token(refresh_token_hash, user)
            .await
    }
    async fn blacklist_jwts(&self, user: &UserId) -> Result<HashSet<u64>> {
        self.backend_handler.blacklist_jwts(user).await
    }
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()> {
        self.backend_handler
            .delete_refresh_token(refresh_token_hash)
            .await
    }
    async fn start_password_reset(&self, user: &UserId) -> Result<Option<String>> {
        self.backend_handler.start_password_reset(user).await
    }
    async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<UserId> {
        self.backend_handler
            .get_user_id_for_password_reset_token(token)
            .await
    }
    async fn delete_password_reset_token(&self, token: &str) -> Result<()> {
        self.backend_handler
            .delete_password_reset_token(token)
            .await
    }
}

// TODO: move somewhere else
#[async_trait]
pub trait LdapEventHandler: Clone + Send + Sync {
    async fn on_ldap_bind(&self, request: &LdapBindRequest, bind_result: BindResult) -> BindResult;
    async fn on_ldap_unbind(&self, user_id: Option<UserId>) -> ();
    async fn on_ldap_modify(
        &self,
        modify_request: LdapModifyRequest,
        modify_result: Vec<LdapOp>,
    ) -> Vec<LdapOp>;
    async fn on_ldap_extended_request(
        &self,
        request: LdapExtendedRequest,
        result: Vec<LdapOp>,
    ) -> Vec<LdapOp>;
    async fn on_password_update(&self, user_id: &UserId, password: &String) -> ();
    async fn on_ldap_search_result(
        &self,
        request: &LdapSearchRequest,
        search_result: InternalSearchResults,
    ) -> InternalSearchResults;
    async fn on_ldap_root_dse(
        &self,
        search_result_entry: LdapSearchResultEntry,
    ) -> LdapSearchResultEntry;
}

#[async_trait]
impl LdapEventHandler for PluginBackendHandler {
    #[instrument(skip_all(), level = "debug")]
    async fn on_ldap_bind(&self, request: &LdapBindRequest, bind_result: BindResult) -> BindResult {
        let context = self.new_plugin_context();
        self.plugin_handler
            .on_ldap_bind(context, request.clone(), bind_result.clone())
            .await
            .unwrap_or(bind_result)
    }
    #[instrument(skip_all(), level = "debug")]
    async fn on_ldap_unbind(&self, user_id: Option<UserId>) -> () {
        if let Some(uid) = user_id {
            let context = self.new_plugin_context();
            let _ = self.plugin_handler.on_ldap_unbind(context, uid).await;
        }
    }
    #[instrument(skip_all(), level = "debug")]
    async fn on_ldap_modify(
        &self,
        modify_request: LdapModifyRequest,
        modify_result: Vec<LdapOp>,
    ) -> Vec<LdapOp> {
        let context = self.new_plugin_context();
        self.plugin_handler
            .on_ldap_modify(context, modify_request.clone(), modify_result.clone())
            .await
            .unwrap_or(modify_result)
    }
    #[instrument(skip_all(), level = "debug")]
    async fn on_ldap_extended_request(
        &self,
        request: LdapExtendedRequest,
        result: Vec<LdapOp>,
    ) -> Vec<LdapOp> {
        let context = self.new_plugin_context();
        self.plugin_handler
            .on_ldap_extended_request(context, request.clone(), result.clone())
            .await
            .unwrap_or(result)
    }
    #[instrument(skip(self, password), level = "debug")]
    async fn on_password_update(&self, user_id: &UserId, password: &String) -> () {
        let context = self.new_plugin_context();
        let _ = self
            .plugin_handler
            .on_ldap_password_update(context, user_id.clone(), password.clone())
            .await;
    }
    #[instrument(skip_all(), level = "debug")]
    async fn on_ldap_search_result(
        &self,
        request: &LdapSearchRequest,
        search_result: InternalSearchResults,
    ) -> InternalSearchResults {
        let context = self.new_plugin_context();
        self.plugin_handler
            .on_ldap_search_result(context, request.clone(), search_result.clone().into())
            .await
            .map(SearchResult::into)
            .unwrap_or(search_result)
    }
    #[instrument(skip_all(), level = "debug")]
    async fn on_ldap_root_dse(
        &self,
        search_result_entry: LdapSearchResultEntry,
    ) -> LdapSearchResultEntry {
        let context = self.new_plugin_context();
        self.plugin_handler
            .on_ldap_root_dse(context, search_result_entry.clone())
            .await
            .unwrap_or(search_result_entry)
    }
}

// TODO: move someehere else
#[cfg(test)]
#[derive(Clone)]
pub struct TestLdapEventHandler {}
#[cfg(test)]
impl TestLdapEventHandler {
    pub fn new() -> Self {
        Self {}
    }
}
#[cfg(test)]
#[async_trait]
impl LdapEventHandler for TestLdapEventHandler {
    async fn on_ldap_bind(
        &self,
        _request: &LdapBindRequest,
        bind_result: BindResult,
    ) -> BindResult {
        bind_result
    }
    async fn on_ldap_unbind(&self, _user_id: Option<UserId>) -> () {
        ()
    }
    async fn on_ldap_modify(
        &self,
        _modify_request: LdapModifyRequest,
        modify_result: Vec<LdapOp>,
    ) -> Vec<LdapOp> {
        modify_result
    }
    async fn on_ldap_extended_request(
        &self,
        _request: LdapExtendedRequest,
        result: Vec<LdapOp>,
    ) -> Vec<LdapOp> {
        result
    }
    async fn on_password_update(&self, _user_id: &UserId, _password: &String) -> () {
        ()
    }
    async fn on_ldap_search_result(
        &self,
        _request: &LdapSearchRequest,
        search_result: InternalSearchResults,
    ) -> InternalSearchResults {
        search_result
    }
    async fn on_ldap_root_dse(
        &self,
        search_result_entry: LdapSearchResultEntry,
    ) -> LdapSearchResultEntry {
        search_result_entry
    }
}
