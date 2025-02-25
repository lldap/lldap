use std::collections::HashSet;

use async_trait::async_trait;
use lldap_auth::access_control::{Permission, ValidationResults};
use lldap_domain_handlers::handler::{
    BackendHandler, GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter,
    ReadSchemaBackendHandler, SchemaBackendHandler, UserBackendHandler, UserListerBackendHandler,
    UserRequestFilter,
};
use tracing::info;

use crate::domain::schema::PublicSchema;
use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    schema::{AttributeSchema, Schema},
    types::{
        AttributeName, Group, GroupDetails, GroupId, GroupName, LdapObjectClass, User,
        UserAndGroups, UserId,
    },
};
use lldap_domain_model::error::Result;

#[async_trait]
pub trait UserReadableBackendHandler: ReadSchemaBackendHandler {
    async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
    async fn get_schema(&self) -> Result<PublicSchema>;
}

#[async_trait]
pub trait ReadonlyBackendHandler: UserReadableBackendHandler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>>;
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
}

#[async_trait]
pub trait UserWriteableBackendHandler: UserReadableBackendHandler {
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
}

#[async_trait]
pub trait AdminBackendHandler:
    UserWriteableBackendHandler
    + ReadonlyBackendHandler
    + UserWriteableBackendHandler
    + SchemaBackendHandler
{
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn delete_user(&self, user_id: &UserId) -> Result<()>;
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId>;
    async fn delete_group(&self, group_id: GroupId) -> Result<()>;
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()>;
    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()>;
    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
}

#[async_trait]
impl<Handler: BackendHandler> UserReadableBackendHandler for Handler {
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        <Handler as UserBackendHandler>::get_user_details(self, user_id).await
    }
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        <Handler as UserBackendHandler>::get_user_groups(self, user_id).await
    }
    async fn get_schema(&self) -> Result<PublicSchema> {
        Ok(PublicSchema::from(
            <Handler as ReadSchemaBackendHandler>::get_schema(self).await?,
        ))
    }
}

#[async_trait]
impl<Handler: BackendHandler> ReadonlyBackendHandler for Handler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        <Handler as UserListerBackendHandler>::list_users(self, filters, get_groups).await
    }
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        <Handler as GroupListerBackendHandler>::list_groups(self, filters).await
    }
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails> {
        <Handler as GroupBackendHandler>::get_group_details(self, group_id).await
    }
}

#[async_trait]
impl<Handler: BackendHandler> UserWriteableBackendHandler for Handler {
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        <Handler as UserBackendHandler>::update_user(self, request).await
    }
}
#[async_trait]
impl<Handler: BackendHandler> AdminBackendHandler for Handler {
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        <Handler as UserBackendHandler>::create_user(self, request).await
    }
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        <Handler as UserBackendHandler>::delete_user(self, user_id).await
    }
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        <Handler as UserBackendHandler>::add_user_to_group(self, user_id, group_id).await
    }
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        <Handler as UserBackendHandler>::remove_user_from_group(self, user_id, group_id).await
    }
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        <Handler as GroupBackendHandler>::update_group(self, request).await
    }
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId> {
        <Handler as GroupBackendHandler>::create_group(self, request).await
    }
    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        <Handler as GroupBackendHandler>::delete_group(self, group_id).await
    }
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_user_attribute(self, request).await
    }
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_group_attribute(self, request).await
    }
    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_user_attribute(self, name).await
    }
    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_group_attribute(self, name).await
    }
    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_user_object_class(self, name).await
    }
    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_group_object_class(self, name).await
    }
    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_user_object_class(self, name).await
    }
    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_group_object_class(self, name).await
    }
}

pub struct AccessControlledBackendHandler<Handler> {
    handler: Handler,
}

impl<Handler: Clone> Clone for AccessControlledBackendHandler<Handler> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
        }
    }
}

impl<Handler> AccessControlledBackendHandler<Handler> {
    pub fn unsafe_get_handler(&self) -> &Handler {
        &self.handler
    }
}

impl<Handler: BackendHandler> AccessControlledBackendHandler<Handler> {
    pub fn new(handler: Handler) -> Self {
        Self { handler }
    }

    pub fn get_schema_only_handler(
        &self,
        _validation_result: &ValidationResults,
    ) -> Option<&impl ReadSchemaBackendHandler> {
        Some(&self.handler)
    }

    pub fn get_admin_handler(
        &self,
        validation_result: &ValidationResults,
    ) -> Option<&impl AdminBackendHandler> {
        validation_result.is_admin().then_some(&self.handler)
    }

    pub fn get_readonly_handler(
        &self,
        validation_result: &ValidationResults,
    ) -> Option<&impl ReadonlyBackendHandler> {
        validation_result.can_read_all().then_some(&self.handler)
    }

    pub fn get_writeable_handler(
        &self,
        validation_result: &ValidationResults,
        user_id: &UserId,
    ) -> Option<&impl UserWriteableBackendHandler> {
        validation_result
            .can_write(user_id)
            .then_some(&self.handler)
    }

    pub fn get_readable_handler(
        &self,
        validation_result: &ValidationResults,
        user_id: &UserId,
    ) -> Option<&impl UserReadableBackendHandler> {
        validation_result.can_read(user_id).then_some(&self.handler)
    }

    pub fn get_user_restricted_lister_handler(
        &self,
        validation_result: &ValidationResults,
    ) -> UserRestrictedListerBackendHandler<'_, Handler> {
        UserRestrictedListerBackendHandler {
            handler: &self.handler,
            user_filter: if validation_result.can_read_all() {
                None
            } else {
                info!("Unprivileged search, limiting results");
                Some(validation_result.user.clone())
            },
        }
    }

    pub async fn get_permissions_for_user(&self, user_id: UserId) -> Result<ValidationResults> {
        let user_groups = self.handler.get_user_groups(&user_id).await?;
        Ok(self.get_permissions_from_groups(user_id, user_groups.iter().map(|g| &g.display_name)))
    }

    pub fn get_permissions_from_groups<Groups, T>(
        &self,
        user_id: UserId,
        groups: Groups,
    ) -> ValidationResults
    where
        Groups: Iterator<Item = T> + Clone,
        T: AsRef<GroupName>,
    {
        let is_in_group = |name: GroupName| groups.clone().any(|g| *g.as_ref() == name);
        ValidationResults {
            user: user_id,
            permission: if is_in_group("lldap_admin".into()) {
                Permission::Admin
            } else if is_in_group("lldap_password_manager".into()) {
                Permission::PasswordManager
            } else if is_in_group("lldap_strict_readonly".into()) {
                Permission::Readonly
            } else {
                Permission::Regular
            },
        }
    }
}

pub struct UserRestrictedListerBackendHandler<'a, Handler> {
    handler: &'a Handler,
    pub user_filter: Option<UserId>,
}

#[async_trait]
impl<Handler: ReadSchemaBackendHandler + Sync> ReadSchemaBackendHandler
    for UserRestrictedListerBackendHandler<'_, Handler>
{
    async fn get_schema(&self) -> Result<Schema> {
        let mut schema = self.handler.get_schema().await?;
        if self.user_filter.is_some() {
            let filter_attributes = |attributes: &mut Vec<AttributeSchema>| {
                attributes.retain(|a| a.is_visible);
            };
            filter_attributes(&mut schema.user_attributes.attributes);
            filter_attributes(&mut schema.group_attributes.attributes);
        }
        Ok(schema)
    }
}

#[async_trait]
impl<Handler: UserListerBackendHandler + Sync> UserListerBackendHandler
    for UserRestrictedListerBackendHandler<'_, Handler>
{
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        let user_filter = self
            .user_filter
            .as_ref()
            .map(|u| UserRequestFilter::UserId(u.clone()));
        let filters = match (filters, user_filter) {
            (None, None) => None,
            (None, u) => u,
            (f, None) => f,
            (Some(f), Some(u)) => Some(UserRequestFilter::And(vec![f, u])),
        };
        self.handler.list_users(filters, get_groups).await
    }
}

#[async_trait]
impl<Handler: GroupListerBackendHandler + Sync> GroupListerBackendHandler
    for UserRestrictedListerBackendHandler<'_, Handler>
{
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        let group_filter = self
            .user_filter
            .as_ref()
            .map(|u| GroupRequestFilter::Member(u.clone()));
        let filters = match (filters, group_filter) {
            (None, None) => None,
            (None, u) => u,
            (f, None) => f,
            (Some(f), Some(u)) => Some(GroupRequestFilter::And(vec![f, u])),
        };
        self.handler.list_groups(filters).await
    }
}

#[async_trait]
pub trait UserAndGroupListerBackendHandler:
    UserListerBackendHandler + GroupListerBackendHandler
{
}

#[async_trait]
impl<Handler: GroupListerBackendHandler + UserListerBackendHandler + Sync>
    UserAndGroupListerBackendHandler for UserRestrictedListerBackendHandler<'_, Handler>
{
}
