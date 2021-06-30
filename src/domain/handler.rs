use super::error::*;
use async_trait::async_trait;
use std::collections::HashSet;

pub use lldap_model::*;

#[async_trait]
pub trait LoginHandler: Clone + Send {
    async fn bind(&self, request: BindRequest) -> Result<()>;
}

#[async_trait]
pub trait BackendHandler: Clone + Send {
    async fn list_users(&self, request: ListUsersRequest) -> Result<Vec<User>>;
    async fn list_groups(&self) -> Result<Vec<Group>>;
    async fn get_user_details(&self, request: UserDetailsRequest) -> Result<User>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn delete_user(&self, request: DeleteUserRequest) -> Result<()>;
    async fn create_group(&self, request: CreateGroupRequest) -> Result<i32>;
    async fn add_user_to_group(&self, request: AddUserToGroupRequest) -> Result<()>;
    async fn get_user_groups(&self, user: String) -> Result<HashSet<String>>;
}

#[cfg(test)]
mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {
        async fn list_users(&self, request: ListUsersRequest) -> Result<Vec<User>>;
        async fn list_groups(&self) -> Result<Vec<Group>>;
        async fn get_user_details(&self, request: UserDetailsRequest) -> Result<User>;
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn delete_user(&self, request: DeleteUserRequest) -> Result<()>;
        async fn create_group(&self, request: CreateGroupRequest) -> Result<i32>;
        async fn get_user_groups(&self, user: String) -> Result<HashSet<String>>;
        async fn add_user_to_group(&self, request: AddUserToGroupRequest) -> Result<()>;
    }
    #[async_trait]
    impl LoginHandler for TestBackendHandler {
        async fn bind(&self, request: BindRequest) -> Result<()>;
    }
}
