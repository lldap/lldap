use super::sql_tables::*;
use crate::domain::{error::*, sql_tables::Pool};
use crate::infra::configuration::Configuration;
use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use log::*;
use sea_query::{Expr, Order, Query, SimpleExpr, SqliteQueryBuilder};
use sqlx::Row;
use std::collections::HashSet;

pub use lldap_model::*;

#[async_trait]
pub trait BackendHandler: Clone + Send {
    async fn bind(&self, request: BindRequest) -> Result<()>;
    async fn list_users(&self, request: ListUsersRequest) -> Result<Vec<User>>;
    async fn list_groups(&self) -> Result<Vec<Group>>;
    async fn get_user_groups(&self, user: String) -> Result<HashSet<String>>;
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
                debug!(r#"Invalid password for LDAP bind user"#);
                return Err(Error::AuthenticationError(request.name));
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
        Err(Error::AuthenticationError(request.name))
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

    async fn list_groups(&self) -> Result<Vec<Group>> {
        let query: String = Query::select()
            .column(Groups::DisplayName)
            .column(Memberships::UserId)
            .from(Groups::Table)
            .left_join(
                Memberships::Table,
                Expr::tbl(Groups::Table, Groups::GroupId)
                    .equals(Memberships::Table, Memberships::GroupId),
            )
            .order_by(Groups::DisplayName, Order::Asc)
            .order_by(Memberships::UserId, Order::Asc)
            .to_string(SqliteQueryBuilder);

        let mut results = sqlx::query(&query).fetch(&self.sql_pool);
        let mut groups = Vec::new();
        // The rows are ordered by group, user, so we need to group them into vectors.
        {
            let mut current_group = String::new();
            let mut current_users = Vec::new();
            while let Some(row) = results.try_next().await? {
                let display_name = row.get::<String, _>("display_name");
                if display_name != current_group {
                    if !current_group.is_empty() {
                        groups.push(Group {
                            display_name: current_group,
                            users: current_users,
                        });
                        current_users = Vec::new();
                    }
                    current_group = display_name.clone();
                }
                current_users.push(row.get::<String, _>("user_id"));
            }
            groups.push(Group {
                display_name: current_group,
                users: current_users,
            });
        }

        Ok(groups)
    }

    async fn get_user_groups(&self, user: String) -> Result<HashSet<String>> {
        if user == self.config.ldap_user_dn {
            let mut groups = HashSet::new();
            groups.insert("lldap_admin".to_string());
            return Ok(groups);
        }
        let query: String = Query::select()
            .column(Groups::DisplayName)
            .from(Groups::Table)
            .inner_join(
                Memberships::Table,
                Expr::tbl(Groups::Table, Groups::GroupId)
                    .equals(Memberships::Table, Memberships::GroupId),
            )
            .and_where(Expr::col(Memberships::UserId).eq(user))
            .to_string(SqliteQueryBuilder);

        sqlx::query(&query)
            // Extract the group id from the row.
            .map(|row: DbRow| row.get::<String, _>("display_name"))
            .fetch(&self.sql_pool)
            // Collect the vector of rows, each potentially an error.
            .collect::<Vec<sqlx::Result<String>>>()
            .await
            .into_iter()
            // Transform it into a single result (the first error if any), and group the group_ids
            // into a HashSet.
            .collect::<sqlx::Result<HashSet<_>>>()
            // Map the sqlx::Error into a domain::Error.
            .map_err(Error::DatabaseError)
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
        async fn list_groups(&self) -> Result<Vec<Group>>;
        async fn get_user_groups(&self, user: String) -> Result<HashSet<String>>;
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
                name.into(),
                "bob@bob".into(),
                "Bob Böbberson".into(),
                "Bob".into(),
                "Böbberson".into(),
                chrono::NaiveDateTime::from_timestamp(0, 0).into(),
                pass.into(),
            ])
            .to_string(SqliteQueryBuilder);
        sqlx::query(&query).execute(sql_pool).await.unwrap();
    }

    async fn insert_group(sql_pool: &Pool, id: u32, name: &str) {
        let query = Query::insert()
            .into_table(Groups::Table)
            .columns(vec![Groups::GroupId, Groups::DisplayName])
            .values_panic(vec![id.into(), name.into()])
            .to_string(SqliteQueryBuilder);
        sqlx::query(&query).execute(sql_pool).await.unwrap();
    }

    async fn insert_membership(sql_pool: &Pool, group_id: u32, user_id: &str) {
        let query = Query::insert()
            .into_table(Memberships::Table)
            .columns(vec![Memberships::UserId, Memberships::GroupId])
            .values_panic(vec![user_id.into(), group_id.into()])
            .to_string(SqliteQueryBuilder);
        sqlx::query(&query).execute(sql_pool).await.unwrap();
    }

    #[tokio::test]
    async fn test_bind_admin() {
        let sql_pool = get_in_memory_db().await;
        let config = Configuration {
            ldap_user_dn: "admin".to_string(),
            ldap_user_pass: "test".to_string(),
            ..Default::default()
        };
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

    #[tokio::test]
    async fn test_list_groups() {
        let sql_pool = get_initialized_db().await;
        insert_user(&sql_pool, "bob", "bob00").await;
        insert_user(&sql_pool, "patrick", "pass").await;
        insert_user(&sql_pool, "John", "Pa33w0rd!").await;
        insert_group(&sql_pool, 1, "Best Group").await;
        insert_group(&sql_pool, 2, "Worst Group").await;
        insert_membership(&sql_pool, 1, "bob").await;
        insert_membership(&sql_pool, 1, "patrick").await;
        insert_membership(&sql_pool, 2, "patrick").await;
        insert_membership(&sql_pool, 2, "John").await;
        let config = Configuration::default();
        let handler = SqlBackendHandler::new(config, sql_pool);
        assert_eq!(
            handler.list_groups().await.unwrap(),
            vec![
                Group {
                    display_name: "Best Group".to_string(),
                    users: vec!["bob".to_string(), "patrick".to_string()]
                },
                Group {
                    display_name: "Worst Group".to_string(),
                    users: vec!["John".to_string(), "patrick".to_string()]
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_get_user_groups() {
        let sql_pool = get_initialized_db().await;
        insert_user(&sql_pool, "bob", "bob00").await;
        insert_user(&sql_pool, "patrick", "pass").await;
        insert_user(&sql_pool, "John", "Pa33w0rd!").await;
        insert_group(&sql_pool, 1, "Group1").await;
        insert_group(&sql_pool, 2, "Group2").await;
        insert_membership(&sql_pool, 1, "bob").await;
        insert_membership(&sql_pool, 1, "patrick").await;
        insert_membership(&sql_pool, 2, "patrick").await;
        let config = Configuration::default();
        let handler = SqlBackendHandler::new(config, sql_pool);
        let mut bob_groups = HashSet::new();
        bob_groups.insert("Group1".to_string());
        let mut patrick_groups = HashSet::new();
        patrick_groups.insert("Group1".to_string());
        patrick_groups.insert("Group2".to_string());
        assert_eq!(
            handler.get_user_groups("bob".to_string()).await.unwrap(),
            bob_groups
        );
        assert_eq!(
            handler
                .get_user_groups("patrick".to_string())
                .await
                .unwrap(),
            patrick_groups
        );
        assert_eq!(
            handler.get_user_groups("John".to_string()).await.unwrap(),
            HashSet::new()
        );
    }
}
