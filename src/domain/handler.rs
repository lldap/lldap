use super::sql_tables::*;
use crate::domain::sql_tables::Pool;
use crate::infra::configuration::Configuration;
use anyhow::{bail, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use log::*;
use sea_query::{Expr, Order, Query, SimpleExpr, SqliteQueryBuilder};
use sqlx::Row;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct BindRequest {
    pub name: String,
    pub password: String,
}

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum RequestFilter {
    And(Vec<RequestFilter>),
    Or(Vec<RequestFilter>),
    Not(Box<RequestFilter>),
    Equality(String, String),
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct ListUsersRequest {
    pub filters: Option<RequestFilter>,
}

#[derive(sqlx::FromRow)]
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
    async fn bind(&self, request: BindRequest) -> Result<()>;
    async fn list_users(&self, request: ListUsersRequest) -> Result<Vec<User>>;
}

#[derive(Debug, Clone)]
pub struct SqlBackendHandler {
    config: Configuration,
    sql_pool: Pool,
}

impl SqlBackendHandler {
    pub fn new(config: Configuration, sql_pool: Pool) -> Self {
        SqlBackendHandler { config, sql_pool }
    }
}

fn passwords_match(encrypted_password: &str, clear_password: &str) -> bool {
    encrypted_password == clear_password
}

fn get_filter_expr(filter: RequestFilter) -> SimpleExpr {
    use RequestFilter::*;
    fn get_repeated_filter(
        fs: Vec<RequestFilter>,
        field: &dyn Fn(SimpleExpr, SimpleExpr) -> SimpleExpr,
    ) -> SimpleExpr {
        let mut it = fs.into_iter();
        let first_expr = match it.next() {
            None => return Expr::value(true),
            Some(f) => get_filter_expr(f),
        };
        it.fold(first_expr, |e, f| field(e, get_filter_expr(f)))
    }
    match filter {
        And(fs) => get_repeated_filter(fs, &SimpleExpr::and),
        Or(fs) => get_repeated_filter(fs, &SimpleExpr::or),
        Not(f) => Expr::not(Expr::expr(get_filter_expr(*f))),
        Equality(s1, s2) => Expr::expr(Expr::cust(&s1)).eq(s2),
    }
}

#[async_trait]
impl BackendHandler for SqlBackendHandler {
    async fn bind(&self, request: BindRequest) -> Result<()> {
        if request.name == self.config.ldap_user_dn {
            if request.password == self.config.ldap_user_pass {
                return Ok(());
            } else {
                bail!(r#"Authentication error for "{}""#, request.name)
            }
        }
        let query = Query::select()
            .column(Users::Password)
            .from(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(request.name.as_str()))
            .to_string(SqliteQueryBuilder);
        if let Ok(row) = sqlx::query(&query).fetch_one(&self.sql_pool).await {
            if passwords_match(&request.password, &row.get::<String, _>("password")) {
                return Ok(());
            } else {
                debug!(r#"Invalid password for "{}""#, request.name);
            }
        } else {
            debug!(r#"No user found for "{}""#, request.name);
        }
        bail!(r#"Authentication error for "{}""#, request.name)
    }

    async fn list_users(&self, request: ListUsersRequest) -> Result<Vec<User>> {
        let query = {
            let mut query_builder = Query::select()
                .column(Users::UserId)
                .column(Users::Email)
                .column(Users::DisplayName)
                .column(Users::FirstName)
                .column(Users::LastName)
                .column(Users::Avatar)
                .column(Users::CreationDate)
                .from(Users::Table)
                .order_by(Users::UserId, Order::Asc)
                .to_owned();
            if let Some(filter) = request.filters {
                if filter != RequestFilter::And(Vec::new())
                    && filter != RequestFilter::Or(Vec::new())
                {
                    query_builder.and_where(get_filter_expr(filter));
                }
            }

            query_builder.to_string(SqliteQueryBuilder)
        };

        let results = sqlx::query_as::<_, User>(&query)
            .fetch(&self.sql_pool)
            .collect::<Vec<sqlx::Result<User>>>()
            .await;

        Ok(results.into_iter().collect::<sqlx::Result<Vec<User>>>()?)
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
        async fn bind(&self, request: BindRequest) -> Result<()>;
        async fn list_users(&self, request: ListUsersRequest) -> Result<Vec<User>>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::sql_tables::init_table;

    async fn get_in_memory_db() -> Pool {
        PoolOptions::new().connect("sqlite::memory:").await.unwrap()
    }

    async fn get_initialized_db() -> Pool {
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        sql_pool
    }

    async fn insert_user(sql_pool: &Pool, name: &str, pass: &str) {
        /*
        let query = Query::insert()
            .into_table(Users::Table)
            .columns(vec![
                Users::UserId,
                Users::Email,
                Users::DisplayName,
                Users::FirstName,
                Users::LastName,
                Users::CreationDate,
                Users::Password,
            ])
            .values_panic(vec![
                "bob".into(),
                "bob@bob".into(),
                "Bob Böbberson".into(),
                "Bob".into(),
                "Böbberson".into(),
                chrono::NaiveDateTime::from_timestamp(0, 0).into(),
                "bob00".into(),
            ])
            .to_string(SqliteQueryBuilder);
        sqlx::query(&query).execute(&sql_pool).await.unwrap();
        */
        sqlx::query(
            r#"INSERT INTO users
      (user_id, email, display_name, first_name, last_name, creation_date, password)
      VALUES (?, "em@ai.l", "Display Name", "Firstname", "Lastname", "1970-01-01 00:00:00", ?)"#,
        )
        .bind(name.to_string())
        .bind(pass.to_string())
        .execute(sql_pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_bind_admin() {
        let sql_pool = get_in_memory_db().await;
        let mut config = Configuration::default();
        config.ldap_user_dn = "admin".to_string();
        config.ldap_user_pass = "test".to_string();
        let handler = SqlBackendHandler::new(config, sql_pool);
        handler
            .bind(BindRequest {
                name: "admin".to_string(),
                password: "test".to_string(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_bind_user() {
        let sql_pool = get_initialized_db().await;
        insert_user(&sql_pool, "bob", "bob00").await;
        let config = Configuration::default();
        let handler = SqlBackendHandler::new(config, sql_pool);
        handler
            .bind(BindRequest {
                name: "bob".to_string(),
                password: "bob00".to_string(),
            })
            .await
            .unwrap();
        handler
            .bind(BindRequest {
                name: "andrew".to_string(),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
        handler
            .bind(BindRequest {
                name: "bob".to_string(),
                password: "wrong_password".to_string(),
            })
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn test_list_users() {
        let sql_pool = get_initialized_db().await;
        insert_user(&sql_pool, "bob", "bob00").await;
        insert_user(&sql_pool, "patrick", "pass").await;
        insert_user(&sql_pool, "John", "Pa33w0rd!").await;
        let config = Configuration::default();
        let handler = SqlBackendHandler::new(config, sql_pool);
        {
            let users = handler
                .list_users(ListUsersRequest { filters: None })
                .await
                .unwrap()
                .into_iter()
                .map(|u| u.user_id)
                .collect::<Vec<_>>();
            assert_eq!(users, vec!["John", "bob", "patrick"]);
        }
        {
            let users = handler
                .list_users(ListUsersRequest {
                    filters: Some(RequestFilter::Equality(
                        "user_id".to_string(),
                        "bob".to_string(),
                    )),
                })
                .await
                .unwrap()
                .into_iter()
                .map(|u| u.user_id)
                .collect::<Vec<_>>();
            assert_eq!(users, vec!["bob"]);
        }
        {
            let users = handler
                .list_users(ListUsersRequest {
                    filters: Some(RequestFilter::Or(vec![
                        RequestFilter::Equality("user_id".to_string(), "bob".to_string()),
                        RequestFilter::Equality("user_id".to_string(), "John".to_string()),
                    ])),
                })
                .await
                .unwrap()
                .into_iter()
                .map(|u| u.user_id)
                .collect::<Vec<_>>();
            assert_eq!(users, vec!["John", "bob"]);
        }
        {
            let users = handler
                .list_users(ListUsersRequest {
                    filters: Some(RequestFilter::Not(Box::new(RequestFilter::Equality(
                        "user_id".to_string(),
                        "bob".to_string(),
                    )))),
                })
                .await
                .unwrap()
                .into_iter()
                .map(|u| u.user_id)
                .collect::<Vec<_>>();
            assert_eq!(users, vec!["John", "patrick"]);
        }
    }
}
