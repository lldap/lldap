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
        arguments::{ldap_bind_result::BindResult, ldap_search_result::SearchResult},
        backend::BackendAPI,
        handler::{PluginHandler, PluginHandlerEvents},
        types::PluginContext,
    },
    internal::{
        arguments::create_user::CreateUserArguments,
        context::plugin_context::LuaPluginContext,
        exec::{exec_mutation_handler, exec_notification_handler},
    },
};

use tracing::{debug, debug_span, instrument, Instrument};

use super::{
    arguments::{
        bind_request::BindRequestArguments, create_group::CreateGroupArguments,
        delete_group::DeleteGroupArguments, delete_user::DeleteUserArguments,
        extended_request::ExtendedRequestArguments,
        ldap_search_result_entry::LdapSearchResultEntryArguments,
        modify_request::ModifyRequestArguments, search_result::SearchResultArguments,
        update_group::UpdateGroupArguments, update_password::UpdatePasswordArguments,
        update_user::UpdateUserArguments, user_and_group::UserAndGroupArguments,
    },
    types::plugins::Plugin,
};

#[async_trait]
impl<KVStore: KeyValueStore<ScopeAndKey> + 'static> PluginHandlerEvents for PluginHandler<KVStore> {
    #[instrument(skip(self, context), level = "debug", err)]
    async fn initialize_plugins<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
    ) -> Result<(), String> {
        if !self.plugin_registry.init.is_empty() {
            // Execute and notify the registered plugins
            for cb in self.plugin_registry.init.iter() {
                // Obtain reference to plugin being executed
                let plugin_ref: &Plugin = cb.plugin.as_ref();
                // Prepare actual context for plugin
                let ctx = LuaPluginContext {
                    api: context.api,
                    configuration: plugin_ref.configuration.clone(),
                    credentials: None,
                    kvstore: self.kvstore.clone(),
                    kvscope: plugin_ref.kvstore_scope.clone(),
                    lua: self.plugin_registry.lua,
                };
                let plugin_name = plugin_ref.name.clone();
                let span = debug_span!("[Lua Plugin Handler]");
                span.in_scope(|| {
                    debug!(plugin_name);
                });
                let _: () = cb
                    .callback
                    .call_async(ctx.clone())
                    .instrument(span)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    #[instrument(skip(self, context), level = "debug", err, fields(user_id = ?args.user_id.as_str()))]
    async fn on_create_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateUserRequest,
    ) -> Result<CreateUserRequest, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_create_user,
            CreateUserArguments::from(args),
        )
        .await?
        .into_request())
    }

    #[instrument(skip(self, context), level = "debug", err, fields(user_id = ?args.user_id.as_str()))]
    async fn on_created_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateUserRequest,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_created_user,
            CreateUserArguments::from(args),
        )
        .await
    }

    #[instrument(skip(self, context), level = "debug", err, fields(user_id = ?args.user_id.as_str()))]
    async fn on_update_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateUserRequest,
    ) -> Result<UpdateUserRequest, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_update_user,
            UpdateUserArguments::from(args),
        )
        .await?
        .into_request())
    }

    #[instrument(skip(self, context), level = "debug", err, fields(user_id = ?args.user_id.as_str()))]
    async fn on_updated_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateUserRequest,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_updated_user,
            UpdateUserArguments::from(args),
        )
        .await
    }

    #[instrument(skip(self, context), level = "debug", err)]
    async fn on_delete_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
    ) -> Result<UserId, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_delete_user,
            DeleteUserArguments::from(user_id),
        )
        .await?
        .into_user_id())
    }

    #[instrument(skip(self, context), level = "debug", err)]
    async fn on_deleted_user<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_deleted_user,
            DeleteUserArguments::from(user_id),
        )
        .await
    }

    #[instrument(skip(self, context), level = "debug", err, fields(display_name = ?args.display_name.as_str()))]
    async fn on_create_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateGroupRequest,
    ) -> Result<CreateGroupRequest, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_create_group,
            CreateGroupArguments::from(args),
        )
        .await?
        .into_request())
    }

    #[instrument(skip(self, context), level = "debug", err, fields(display_name = ?args.display_name.as_str()))]
    async fn on_created_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: CreateGroupRequest,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_created_group,
            CreateGroupArguments::from(args),
        )
        .await
    }

    #[instrument(skip(self, context, args), level = "debug", err)]
    async fn on_update_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateGroupRequest,
    ) -> Result<UpdateGroupRequest, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_update_group,
            UpdateGroupArguments::from(args),
        )
        .await?
        .into_request())
    }

    #[instrument(skip(self, context, args), level = "debug")]
    async fn on_updated_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        args: UpdateGroupRequest,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_updated_group,
            UpdateGroupArguments::from(args),
        )
        .await
    }

    #[instrument(skip(self, context), level = "debug", err)]
    async fn on_delete_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        group_id: GroupId,
    ) -> Result<GroupId, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_delete_group,
            DeleteGroupArguments::from(group_id),
        )
        .await?
        .into_group_id())
    }

    #[instrument(skip(self, context), level = "debug", err)]
    async fn on_deleted_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        group_id: GroupId,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_deleted_group,
            DeleteGroupArguments::from(group_id),
        )
        .await
    }

    #[instrument(skip(self, context), level = "debug", err)]
    async fn on_added_user_to_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_added_user_to_group,
            UserAndGroupArguments::from(user_id, group_id),
        )
        .await
    }

    #[instrument(skip(self, context), level = "debug", err)]
    async fn on_removed_user_from_group<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_removed_user_from_group,
            UserAndGroupArguments::from(user_id, group_id),
        )
        .await
    }

    #[instrument(skip(self, context, bind_request), level = "debug", err)]
    async fn on_ldap_bind<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        bind_request: LdapBindRequest,
        bind_result: BindResult,
    ) -> Result<BindResult, String> {
        exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_ldap_bind,
            BindRequestArguments::new(bind_result, bind_request),
        )
        .await
        .map(|r| r.bind_result)
    }

    #[instrument(skip(self, context), level = "debug", err)]
    async fn on_ldap_unbind<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_ldap_unbind,
            user_id.into_string(),
        )
        .await
    }

    #[instrument(skip_all(), level = "debug", err)]
    async fn on_ldap_modify<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        modify_request: LdapModifyRequest,
        modify_result: Vec<LdapOp>,
    ) -> Result<Vec<LdapOp>, String> {
        exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_ldap_modify,
            ModifyRequestArguments::new(modify_result, modify_request),
        )
        .await
        .map(|r| r.modify_result)
    }

    #[instrument(skip_all(), level = "debug", err)]
    async fn on_ldap_extended_request<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        request: LdapExtendedRequest,
        result: Vec<LdapOp>,
    ) -> Result<Vec<LdapOp>, String> {
        exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_ldap_extended_request,
            ExtendedRequestArguments::new(result, request),
        )
        .await
        .map(|r| r.extended_result)
    }

    #[instrument(skip(self, context, password), level = "debug", err)]
    async fn on_ldap_password_update<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        user_id: UserId,
        password: String,
    ) -> Result<(), String> {
        exec_notification_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_ldap_password_update,
            UpdatePasswordArguments::from(user_id, password),
        )
        .await
    }

    #[instrument(skip_all(), level = "debug", err)]
    async fn on_ldap_search_result<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        search_request: LdapSearchRequest,
        search_result: SearchResult,
    ) -> Result<SearchResult, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_ldap_search_result,
            SearchResultArguments::new(search_result, search_request),
        )
        .await?
        .search_result
        .into())
    }

    #[instrument(skip_all(), level = "debug", err)]
    async fn on_ldap_root_dse<A: BackendAPI>(
        &self,
        context: PluginContext<A>,
        search_result_entry: LdapSearchResultEntry,
    ) -> Result<LdapSearchResultEntry, String> {
        Ok(exec_mutation_handler(
            context,
            self.kvstore.clone(),
            &self.plugin_registry.lua,
            &self.plugin_registry.on_ldap_root_dse,
            LdapSearchResultEntryArguments::new(search_result_entry),
        )
        .await?
        .search_result_entry)
    }
}
