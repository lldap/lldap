use std::collections::HashSet;

use async_trait::async_trait;
use tracing::info;

use crate::domain::{
    error::Result,
    handler::{
        BackendHandler, CreateUserRequest, GroupListerBackendHandler, GroupRequestFilter,
        UpdateGroupRequest, UpdateUserRequest, UserListerBackendHandler, UserRequestFilter,
    },
    types::{Group, GroupDetails, GroupId, User, UserAndGroups, UserId},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Permission {
    Admin,
    PasswordManager,
    Readonly,
    Regular,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResults {
    pub user: UserId,
    pub permission: Permission,
}

impl ValidationResults {
    #[cfg(test)]
    pub fn admin() -> Self {
        Self {
            user: UserId::new("admin"),
            permission: Permission::Admin,
        }
    }

    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.permission == Permission::Admin
    }

    #[must_use]
    pub fn can_read_all(&self) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::Readonly
            || self.permission == Permission::PasswordManager
    }

    #[must_use]
    pub fn can_read(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::PasswordManager
            || self.permission == Permission::Readonly
            || &self.user == user
    }

    #[must_use]
    pub fn can_change_password(&self, user: &UserId, user_is_admin: bool) -> bool {
        self.permission == Permission::Admin
            || (self.permission == Permission::PasswordManager && !user_is_admin)
            || &self.user == user
    }

    #[must_use]
    pub fn can_write(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin || &self.user == user
    }
}

#[async_trait]
pub trait UserReadableBackendHandler {
    async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
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
    UserWriteableBackendHandler + ReadonlyBackendHandler + UserWriteableBackendHandler
{
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn delete_user(&self, user_id: &UserId) -> Result<()>;
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
    async fn create_group(&self, group_name: &str) -> Result<GroupId>;
    async fn delete_group(&self, group_id: GroupId) -> Result<()>;
}

#[async_trait]
impl<Handler: BackendHandler> UserReadableBackendHandler for Handler {
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        self.get_user_details(user_id).await
    }
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        self.get_user_groups(user_id).await
    }
}

#[async_trait]
impl<Handler: BackendHandler> ReadonlyBackendHandler for Handler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        self.list_users(filters, get_groups).await
    }
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        self.list_groups(filters).await
    }
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails> {
        self.get_group_details(group_id).await
    }
}

#[async_trait]
impl<Handler: BackendHandler> UserWriteableBackendHandler for Handler {
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        self.update_user(request).await
    }
}
#[async_trait]
impl<Handler: BackendHandler> AdminBackendHandler for Handler {
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        self.create_user(request).await
    }
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        self.delete_user(user_id).await
    }
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        self.add_user_to_group(user_id, group_id).await
    }
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        self.remove_user_from_group(user_id, group_id).await
    }
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        self.update_group(request).await
    }
    async fn create_group(&self, group_name: &str) -> Result<GroupId> {
        self.create_group(group_name).await
    }
    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        self.delete_group(group_id).await
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

    pub fn get_permissions_from_groups<'a, Groups: Iterator<Item = &'a String> + Clone + 'a>(
        &self,
        user_id: UserId,
        groups: Groups,
    ) -> ValidationResults {
        let is_in_group = |name| groups.clone().any(|g| g == name);
        ValidationResults {
            user: user_id,
            permission: if is_in_group("lldap_admin") {
                Permission::Admin
            } else if is_in_group("lldap_password_manager") {
                Permission::PasswordManager
            } else if is_in_group("lldap_strict_readonly") {
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
impl<'a, Handler: UserListerBackendHandler + Sync> UserListerBackendHandler
    for UserRestrictedListerBackendHandler<'a, Handler>
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
impl<'a, Handler: GroupListerBackendHandler + Sync> GroupListerBackendHandler
    for UserRestrictedListerBackendHandler<'a, Handler>
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
impl<'a, Handler: GroupListerBackendHandler + UserListerBackendHandler + Sync>
    UserAndGroupListerBackendHandler for UserRestrictedListerBackendHandler<'a, Handler>
{
}
