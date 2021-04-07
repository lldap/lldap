use crate::infra::configuration::Configuration;
use anyhow::{bail, Result};
use async_trait::async_trait;
use sqlx::any::AnyPool;
use sqlx::Row;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct BindRequest {
    pub name: String,
    pub password: String,
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct ListUsersRequest {
    // filters
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    // pub avatar: ?,
    pub creation_date: chrono::NaiveDateTime,
}

#[async_trait]
pub trait BackendHandler: Clone + Send {
    async fn bind(&mut self, request: BindRequest) -> Result<()>;
    async fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>>;
}

#[derive(Debug, Clone)]
pub struct SqlBackendHandler {
    config: Configuration,
    sql_pool: AnyPool,
    authenticated: bool,
}

impl SqlBackendHandler {
    pub fn new(config: Configuration, sql_pool: AnyPool) -> Self {
        SqlBackendHandler {
            config,
            sql_pool,
            authenticated: false,
        }
    }
}

fn passwords_match(encrypted_password: &str, clear_password: &str) -> bool {
    encrypted_password == clear_password
}

#[async_trait]
impl BackendHandler for SqlBackendHandler {
    async fn bind(&mut self, request: BindRequest) -> Result<()> {
        if request.name == self.config.ldap_user_dn {
            if request.password == self.config.ldap_user_pass {
                self.authenticated = true;
                return Ok(());
            } else {
                bail!(r#"Authentication error for "{}""#, request.name)
            }
        }
        if let Ok(row) = sqlx::query("SELECT password FROM users WHERE user_id = ?")
            .bind(&request.name)
            .fetch_one(&self.sql_pool)
            .await
        {
            if passwords_match(&request.password, &row.get::<String, _>("password")) {
                return Ok(());
            }
        }
        bail!(r#"Authentication error for "{}""#, request.name)
    }

    async fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {
        async fn bind(&mut self, request: BindRequest) -> Result<()>;
        async fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>>;
    }
}
