use super::error::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(sqlx::FromRow))]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    // pub avatar: ?,
    pub creation_date: chrono::DateTime<chrono::Utc>,
}

impl Default for User {
    fn default() -> Self {
        use chrono::TimeZone;
        User {
            user_id: String::new(),
            email: String::new(),
            display_name: String::new(),
            first_name: String::new(),
            last_name: String::new(),
            creation_date: chrono::Utc.timestamp(0, 0),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub display_name: String,
    pub users: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct BindRequest {
    pub name: String,
    pub password: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub enum RequestFilter {
    And(Vec<RequestFilter>),
    Or(Vec<RequestFilter>),
    Not(Box<RequestFilter>),
    Equality(String, String),
    // Check if a user belongs to a group identified by name.
    MemberOf(String),
    // Same, by id.
    MemberOfId(GroupId),
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct CreateUserRequest {
    // Same fields as User, but no creation_date, and with password.
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct UpdateUserRequest {
    // Same fields as CreateUserRequest, but no with an extra layer of Option.
    pub user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct UpdateGroupRequest {
    pub group_id: GroupId,
    pub display_name: Option<String>,
}

#[async_trait]
pub trait LoginHandler: Clone + Send {
    async fn bind(&self, request: BindRequest) -> Result<()>;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub i32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::FromRow)]
pub struct GroupIdAndName(pub GroupId, pub String);

#[async_trait]
pub trait BackendHandler: Clone + Send {
    async fn list_users(&self, filters: Option<RequestFilter>) -> Result<Vec<User>>;
    async fn list_groups(&self) -> Result<Vec<Group>>;
    async fn get_user_details(&self, user_id: &str) -> Result<User>;
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupIdAndName>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
    async fn delete_user(&self, user_id: &str) -> Result<()>;
    async fn create_group(&self, group_name: &str) -> Result<GroupId>;
    async fn delete_group(&self, group_id: GroupId) -> Result<()>;
    async fn add_user_to_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
    async fn get_user_groups(&self, user: &str) -> Result<HashSet<GroupIdAndName>>;
}

#[cfg(test)]
mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {
        async fn list_users(&self, filters: Option<RequestFilter>) -> Result<Vec<User>>;
        async fn list_groups(&self) -> Result<Vec<Group>>;
        async fn get_user_details(&self, user_id: &str) -> Result<User>;
        async fn get_group_details(&self, group_id: GroupId) -> Result<GroupIdAndName>;
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
        async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
        async fn delete_user(&self, user_id: &str) -> Result<()>;
        async fn create_group(&self, group_name: &str) -> Result<GroupId>;
        async fn delete_group(&self, group_id: GroupId) -> Result<()>;
        async fn get_user_groups(&self, user: &str) -> Result<HashSet<GroupIdAndName>>;
        async fn add_user_to_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
        async fn remove_user_from_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl LoginHandler for TestBackendHandler {
        async fn bind(&self, request: BindRequest) -> Result<()>;
    }
}
