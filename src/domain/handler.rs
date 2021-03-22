use crate::infra::configuration::Configuration;
use anyhow::{bail, Result};
use sqlx::any::AnyPool;

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

pub trait BackendHandler: Clone + Send {
    fn bind(&mut self, request: BindRequest) -> Result<()>;
    fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>>;
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

impl BackendHandler for SqlBackendHandler {
    fn bind(&mut self, request: BindRequest) -> Result<()> {
        if request.name == self.config.ldap_user_dn
            && request.password == self.config.ldap_user_pass
        {
            self.authenticated = true;
            Ok(())
        } else {
            bail!(r#"Authentication error for "{}""#, request.name)
        }
    }

    fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    impl BackendHandler for TestBackendHandler {
        fn bind(&mut self, request: BindRequest) -> Result<()>;
        fn list_users(&mut self, request: ListUsersRequest) -> Result<Vec<User>>;
    }
}
