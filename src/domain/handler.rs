use super::error::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub use lldap_model::{AddUserToGroupRequest, CreateGroupRequest, DeleteUserRequest, Group, User};

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

#[async_trait]
pub trait LoginHandler: Clone + Send {
    async fn bind(&self, request: BindRequest) -> Result<()>;
}

#[async_trait]
pub trait BackendHandler: Clone + Send {
    async fn list_users(&self, filters: Option<RequestFilter>) -> Result<Vec<User>>;
    async fn list_groups(&self) -> Result<Vec<Group>>;
    async fn get_user_details(&self, user_id: &str) -> Result<User>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn delete_user(&self, request: DeleteUserRequest) -> Result<()>;
    async fn create_group(&self, request: CreateGroupRequest) -> Result<i32>;
    async fn add_user_to_group(&self, request: AddUserToGroupRequest) -> Result<()>;
    async fn get_user_groups(&self, user: &str) -> Result<HashSet<String>>;
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
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn delete_user(&self, request: DeleteUserRequest) -> Result<()>;
        async fn create_group(&self, request: CreateGroupRequest) -> Result<i32>;
        async fn get_user_groups(&self, user: &str) -> Result<HashSet<String>>;
        async fn add_user_to_group(&self, request: AddUserToGroupRequest) -> Result<()>;
    }
    #[async_trait]
    impl LoginHandler for TestBackendHandler {
        async fn bind(&self, request: BindRequest) -> Result<()>;
    }
}
