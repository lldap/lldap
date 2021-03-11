use crate::infra::configuration::Configuration;
use anyhow::{bail, Result};
use sqlx::any::AnyPool;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct BindRequest {
    pub name: String,
    pub password: String,
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct SearchRequest {}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct SearchResponse {}

pub trait BackendHandler: Clone + Send {
    fn bind(&mut self, request: BindRequest) -> Result<()>;
    fn search(&mut self, request: SearchRequest) -> Result<SearchResponse>;
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
        if request.name == self.config.admin_dn && request.password == self.config.admin_password {
            self.authenticated = true;
            Ok(())
        } else {
            bail!(r#"Authentication error for "{}""#, request.name)
        }
    }

    fn search(&mut self, request: SearchRequest) -> Result<SearchResponse> {
        Ok(SearchResponse {})
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
        fn search(&mut self, request: SearchRequest) -> Result<SearchResponse>;
    }
}
