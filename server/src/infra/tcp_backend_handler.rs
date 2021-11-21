use async_trait::async_trait;
use std::collections::HashSet;

use crate::domain::error::Result;

#[async_trait]
pub trait TcpBackendHandler {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
    async fn create_refresh_token(&self, user: &str) -> Result<(String, chrono::Duration)>;
    async fn check_token(&self, refresh_token_hash: u64, user: &str) -> Result<bool>;
    async fn blacklist_jwts(&self, user: &str) -> Result<HashSet<u64>>;
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()>;

    /// Request a token to reset a user's password.
    /// If the user doesn't exist, returns `Ok(None)`, otherwise `Ok(Some(token))`.
    async fn start_password_reset(&self, user: &str) -> Result<Option<String>>;

    /// Get the user ID associated with a password reset token.
    async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<String>;
}

#[cfg(test)]
use crate::domain::handler::*;
#[cfg(test)]
mockall::mock! {
    pub TestTcpBackendHandler{}
    impl Clone for TestTcpBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl LoginHandler for TestTcpBackendHandler {
        async fn bind(&self, request: BindRequest) -> Result<()>;
    }
    #[async_trait]
    impl BackendHandler for TestTcpBackendHandler {
        async fn list_users(&self, filters: Option<RequestFilter>) -> Result<Vec<User>>;
        async fn list_groups(&self) -> Result<Vec<Group>>;
        async fn get_user_details(&self, user_id: &str) -> Result<User>;
        async fn get_group_details(&self, group_id: GroupId) -> Result<GroupIdAndName>;
        async fn get_user_groups(&self, user: &str) -> Result<HashSet<GroupIdAndName>>;
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
        async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
        async fn delete_user(&self, user_id: &str) -> Result<()>;
        async fn create_group(&self, group_name: &str) -> Result<GroupId>;
        async fn delete_group(&self, group_id: GroupId) -> Result<()>;
        async fn add_user_to_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
        async fn remove_user_from_group(&self, user_id: &str, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl TcpBackendHandler for TestTcpBackendHandler {
        async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
        async fn create_refresh_token(&self, user: &str) -> Result<(String, chrono::Duration)>;
        async fn check_token(&self, refresh_token_hash: u64, user: &str) -> Result<bool>;
        async fn blacklist_jwts(&self, user: &str) -> Result<HashSet<u64>>;
        async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()>;
        async fn start_password_reset(&self, user: &str) -> Result<Option<String>>;
        async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<String>;
    }
}
