use std::collections::HashSet;

use async_trait::async_trait;

use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    schema::Schema,
    types::{
        AttributeName, Group, GroupDetails, GroupId, LdapObjectClass, User, UserAndGroups, UserId,
    },
};

//
// BackendAPI trait exposes functionality provided by
// the LLDAP backend, and exposed to individual plugins.
//
#[async_trait]
pub trait BackendAPI: Clone + Sync + Send {
    //
    // User Listing
    //
    async fn list_users_ldap_filter(
        &self,
        filters: Option<String>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>, String>;
    //
    // Group Listing
    //
    async fn list_groups_ldap_filter(&self, filters: Option<String>) -> Result<Vec<Group>, String>;
    //
    // Read Schema
    //
    async fn get_schema(&self) -> Result<Schema, String>;
    //
    // Schema
    //
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<(), String>;
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<(), String>;
    async fn delete_user_attribute(&self, name: AttributeName) -> Result<(), String>;
    async fn delete_group_attribute(&self, name: AttributeName) -> Result<(), String>;
    async fn add_user_object_class(&self, name: LdapObjectClass) -> Result<(), String>;
    async fn add_group_object_class(&self, name: LdapObjectClass) -> Result<(), String>;
    async fn delete_user_object_class(&self, name: LdapObjectClass) -> Result<(), String>;
    async fn delete_group_object_class(&self, name: LdapObjectClass) -> Result<(), String>;
    //
    // Groups
    //
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails, String>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<(), String>;
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId, String>;
    async fn delete_group(&self, group_id: GroupId) -> Result<(), String>;
    //
    // Users
    //
    async fn get_user_details(&self, user_id: &UserId) -> Result<User, String>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<(), String>;
    async fn update_user(&self, request: UpdateUserRequest) -> Result<(), String>;
    async fn delete_user(&self, user_id: &UserId) -> Result<(), String>;
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<(), String>;
    async fn remove_user_from_group(
        &self,
        user_id: &UserId,
        group_id: GroupId,
    ) -> Result<(), String>;
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>, String>;
}
