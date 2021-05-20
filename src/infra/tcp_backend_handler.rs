use std::collections::HashSet;
use async_trait::async_trait;

pub type DomainError = crate::domain::error::Error;
pub type DomainResult<T> = crate::domain::error::Result<T>;

#[async_trait]
pub trait TcpBackendHandler {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
    async fn create_refresh_token(&self, user: &str) -> DomainResult<(String, chrono::Duration)>;
    async fn check_token(&self, token: &str, user: &str) -> DomainResult<bool>;
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
    impl BackendHandler for TestTcpBackendHandler {
        async fn bind(&self, request: BindRequest) -> DomainResult<()>;
        async fn list_users(&self, request: ListUsersRequest) -> DomainResult<Vec<User>>;
        async fn list_groups(&self) -> DomainResult<Vec<Group>>;
        async fn get_user_groups(&self, user: String) -> DomainResult<HashSet<String>>;
    }
    #[async_trait]
    impl TcpBackendHandler for TestTcpBackendHandler {
        async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
        async fn create_refresh_token(&self, user: &str) -> DomainResult<(String, chrono::Duration)>;
        async fn check_token(&self, token: &str, user: &str) -> DomainResult<bool>;
    }
}
