use std::collections::HashSet;

use async_trait::async_trait;

use lldap_auth::types::UserId;
use lldap_plugin_engine::api::backend::BackendAPI;

use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    schema::Schema,
    types::{AttributeName, Group, GroupDetails, GroupId, LdapObjectClass, User, UserAndGroups},
};
use lldap_domain_handlers::handler::{BackendHandler, GroupRequestFilter, UserRequestFilter};

use crate::domain::{
    ldap::{group::convert_group_filter, user::convert_user_filter, utils::LdapInfo},
    schema::PublicSchema,
};

use ldap3_proto::{filter, proto::LdapFilter};
use tracing::instrument;

#[derive(Clone, Debug)]
pub struct ServerBackendAPI<Handler: BackendHandler> {
    pub backend_handler: Handler,
    pub ldap_info: LdapInfo,
}

#[async_trait]
impl<B: BackendHandler + Clone + std::fmt::Debug> BackendAPI for ServerBackendAPI<B> {
    //
    // Read Schema
    //
    #[instrument(skip(self), level = "debug", err)]
    async fn get_schema(&self) -> Result<Schema, String> {
        self.backend_handler
            .get_schema()
            .await
            .map_err(|e| e.to_string())
    }
    //
    // User Listing
    //
    // TODO: should probably just take an enum type instead
    #[instrument(skip(self), level = "debug", err)]
    async fn list_users_ldap_filter(
        &self,
        filters: Option<String>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>, String> {
        let user_filter: Option<UserRequestFilter> = match filters {
            Some(s) => Some(parse_user_filter(
                &self.get_schema().await?,
                &self.ldap_info,
                s,
            )?),
            None => None,
        };
        self.backend_handler
            .list_users(user_filter, get_groups)
            .await
            .map_err(|e| e.to_string())
    }
    //
    // Group Listing
    //
    #[instrument(skip(self), level = "debug", err)]
    async fn list_groups_ldap_filter(&self, filters: Option<String>) -> Result<Vec<Group>, String> {
        let group_filter: Option<GroupRequestFilter> = match filters {
            Some(s) => Some(parse_group_filter(
                &self.get_schema().await?,
                &self.ldap_info,
                s,
            )?),
            None => None,
        };
        self.backend_handler
            .list_groups(group_filter)
            .await
            .map_err(|e| e.to_string())
    }
    //
    // Schema
    //
    #[instrument(skip(self), level = "debug", err)]
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<(), String> {
        self.backend_handler
            .add_user_attribute(request)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<(), String> {
        self.backend_handler
            .add_group_attribute(request)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn delete_user_attribute(&self, name: AttributeName) -> Result<(), String> {
        self.backend_handler
            .delete_user_attribute(&name)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn delete_group_attribute(&self, name: AttributeName) -> Result<(), String> {
        self.backend_handler
            .delete_group_attribute(&name)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn add_user_object_class(&self, name: LdapObjectClass) -> Result<(), String> {
        self.backend_handler
            .add_user_object_class(&name)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn add_group_object_class(&self, name: LdapObjectClass) -> Result<(), String> {
        self.backend_handler
            .add_group_object_class(&name)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn delete_user_object_class(&self, name: LdapObjectClass) -> Result<(), String> {
        self.backend_handler
            .delete_user_object_class(&name)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn delete_group_object_class(&self, name: LdapObjectClass) -> Result<(), String> {
        self.backend_handler
            .delete_group_object_class(&name)
            .await
            .map_err(|e| e.to_string())
    }
    //
    // Groups
    //
    #[instrument(skip(self), level = "debug", err)]
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails, String> {
        self.backend_handler
            .get_group_details(group_id)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<(), String> {
        self.backend_handler
            .update_group(request)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId, String> {
        self.backend_handler
            .create_group(request)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn delete_group(&self, group_id: GroupId) -> Result<(), String> {
        self.backend_handler
            .delete_group(group_id)
            .await
            .map_err(|e| e.to_string())
    }
    //
    // Users
    //
    #[instrument(skip(self), level = "debug", err)]
    async fn get_user_details(&self, user_id: &UserId) -> Result<User, String> {
        self.backend_handler
            .get_user_details(user_id)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn create_user(&self, request: CreateUserRequest) -> Result<(), String> {
        self.backend_handler
            .create_user(request)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn update_user(&self, request: UpdateUserRequest) -> Result<(), String> {
        self.backend_handler
            .update_user(request)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn delete_user(&self, user_id: &UserId) -> Result<(), String> {
        self.backend_handler
            .delete_user(user_id)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<(), String> {
        self.backend_handler
            .add_user_to_group(user_id, group_id)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn remove_user_from_group(
        &self,
        user_id: &UserId,
        group_id: GroupId,
    ) -> Result<(), String> {
        self.backend_handler
            .remove_user_from_group(user_id, group_id)
            .await
            .map_err(|e| e.to_string())
    }
    #[instrument(skip(self), level = "debug", err)]
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>, String> {
        self.backend_handler
            .get_user_groups(user_id)
            .await
            .map_err(|e| e.to_string())
    }
}

fn parse_user_filter(
    schema: &Schema,
    ldap_info: &LdapInfo,
    filter: String,
) -> Result<UserRequestFilter, String> {
    let ldap_filter: LdapFilter =
        filter::parse_ldap_filter_str(filter.as_str()).map_err(|e| e.to_string())?;
    //parse_ldap_user_filter(schema, ldap_info, ldap_filter)
    let pub_schema = PublicSchema::from(schema.clone());
    convert_user_filter(ldap_info, &ldap_filter, &pub_schema).map_err(|e| e.to_string())
}

fn parse_group_filter(
    schema: &Schema,
    ldap_info: &LdapInfo,
    filter: String,
) -> Result<GroupRequestFilter, String> {
    let ldap_filter: LdapFilter =
        filter::parse_ldap_filter_str(filter.as_str()).map_err(|e| e.to_string())?;
    let pub_schema = PublicSchema::from(schema.clone());
    convert_group_filter(ldap_info, &ldap_filter, &pub_schema).map_err(|e| e.to_string())
}
