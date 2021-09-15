use async_trait::async_trait;
use std::collections::HashSet;

pub type DomainResult<T> = crate::domain::error::Result<T>;

#[async_trait]
pub trait TcpBackendHandler {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
    async fn create_refresh_token(&self, user: &str) -> DomainResult<(String, chrono::Duration)>;
    async fn check_token(&self, refresh_token_hash: u64, user: &str) -> DomainResult<bool>;
    async fn blacklist_jwts(&self, user: &str) -> DomainResult<HashSet<u64>>;
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> DomainResult<()>;
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
        async fn bind(&self, request: BindRequest) -> DomainResult<()>;
    }
    #[async_trait]
    impl BackendHandler for TestTcpBackendHandler {
        async fn list_users(&self, filters: Option<RequestFilter>) -> DomainResult<Vec<User>>;
        async fn list_groups(&self) -> DomainResult<Vec<Group>>;
        async fn get_user_details(&self, user_id: &str) -> DomainResult<User>;
        async fn get_user_groups(&self, user: &str) -> DomainResult<HashSet<String>>;
        async fn create_user(&self, request: CreateUserRequest) -> DomainResult<()>;
        async fn update_user(&self, request: UpdateUserRequest) -> DomainResult<()>;
        async fn delete_user(&self, user_id: &str) -> DomainResult<()>;
        async fn create_group(&self, group_name: &str) -> DomainResult<GroupId>;
        async fn add_user_to_group(&self, user_id: &str, group_id: GroupId) -> DomainResult<()>;
        async fn remove_user_from_group(&self, user_id: &str, group_id: GroupId) -> DomainResult<()>;
    }
    #[async_trait]
    impl TcpBackendHandler for TestTcpBackendHandler {
        async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
        async fn create_refresh_token(&self, user: &str) -> DomainResult<(String, chrono::Duration)>;
        async fn check_token(&self, refresh_token_hash: u64, user: &str) -> DomainResult<bool>;
        async fn blacklist_jwts(&self, user: &str) -> DomainResult<HashSet<u64>>;
        async fn delete_refresh_token(&self, refresh_token_hash: u64) -> DomainResult<()>;
    }
}
