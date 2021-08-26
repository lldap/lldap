use super::{error::*, handler::*, sql_tables::*};
use crate::infra::configuration::Configuration;
use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use sea_query::{Expr, Iden, Order, Query, SimpleExpr, Value};
use sqlx::Row;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct SqlBackendHandler {
    pub(crate) config: Configuration,
    pub(crate) sql_pool: Pool,
}

impl SqlBackendHandler {
    pub fn new(config: Configuration, sql_pool: Pool) -> Self {
        SqlBackendHandler { config, sql_pool }
    }
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

            query_builder.to_string(DbQueryBuilder {})
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
            .to_string(DbQueryBuilder {});

        let mut results = sqlx::query(&query).fetch(&self.sql_pool);
        let mut groups = Vec::new();
        // The rows are ordered by group, user, so we need to group them into vectors.
        {
            let mut current_group = String::new();
            let mut current_users = Vec::new();
            while let Some(row) = results.try_next().await? {
                let display_name = row.get::<String, _>(&*Groups::DisplayName.to_string());
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
                current_users.push(row.get::<String, _>(&*Memberships::UserId.to_string()));
            }
            groups.push(Group {
                display_name: current_group,
                users: current_users,
            });
        }

        Ok(groups)
    }

    async fn get_user_details(&self, request: UserDetailsRequest) -> Result<User> {
        let query = Query::select()
            .column(Users::UserId)
            .column(Users::Email)
            .column(Users::DisplayName)
            .column(Users::FirstName)
            .column(Users::LastName)
            .column(Users::Avatar)
            .column(Users::CreationDate)
            .from(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(request.user_id))
            .to_string(DbQueryBuilder {});

        Ok(sqlx::query_as::<_, User>(&query)
            .fetch_one(&self.sql_pool)
            .await?)
    }

    async fn get_user_groups(&self, user: &str) -> Result<HashSet<String>> {
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
            .to_string(DbQueryBuilder {});

        sqlx::query(&query)
            // Extract the group id from the row.
            .map(|row: DbRow| row.get::<String, _>(&*Groups::DisplayName.to_string()))
            .fetch(&self.sql_pool)
            // Collect the vector of rows, each potentially an error.
            .collect::<Vec<sqlx::Result<String>>>()
            .await
            .into_iter()
            // Transform it into a single result (the first error if any), and group the group_ids
            // into a HashSet.
            .collect::<sqlx::Result<HashSet<_>>>()
            // Map the sqlx::Error into a DomainError.
            .map_err(DomainError::DatabaseError)
    }

    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        let columns = vec![
            Users::UserId,
            Users::Email,
            Users::DisplayName,
            Users::FirstName,
            Users::LastName,
            Users::CreationDate,
        ];
        let values = vec![
            request.user_id.clone().into(),
            request.email.into(),
            request.display_name.map(Into::into).unwrap_or(Value::Null),
            request.first_name.map(Into::into).unwrap_or(Value::Null),
            request.last_name.map(Into::into).unwrap_or(Value::Null),
            chrono::Utc::now().naive_utc().into(),
        ];
        let query = Query::insert()
            .into_table(Users::Table)
            .columns(columns)
            .values_panic(values)
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn delete_user(&self, request: DeleteUserRequest) -> Result<()> {
        let delete_query = Query::delete()
            .from_table(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(request.user_id))
            .to_string(DbQueryBuilder {});
        sqlx::query(&delete_query).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn create_group(&self, request: CreateGroupRequest) -> Result<i32> {
        let query = Query::insert()
            .into_table(Groups::Table)
            .columns(vec![Groups::DisplayName])
            .values_panic(vec![request.display_name.as_str().into()])
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        let query = Query::select()
            .column(Groups::GroupId)
            .from(Groups::Table)
            .and_where(Expr::col(Groups::DisplayName).eq(request.display_name.as_str()))
            .to_string(DbQueryBuilder {});
        let row = sqlx::query(&query).fetch_one(&self.sql_pool).await?;
        Ok(row.get::<i32, _>(&*Groups::GroupId.to_string()))
    }

    async fn add_user_to_group(&self, request: AddUserToGroupRequest) -> Result<()> {
        let query = Query::insert()
            .into_table(Memberships::Table)
            .columns(vec![Memberships::UserId, Memberships::GroupId])
            .values_panic(vec![request.user_id.into(), request.group_id.into()])
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::sql_tables::init_table;
    use crate::infra::configuration::ConfigurationBuilder;

    fn get_default_config() -> Configuration {
        ConfigurationBuilder::default()
            .verbose(true)
            .build()
            .unwrap()
    }

    async fn get_in_memory_db() -> Pool {
        PoolOptions::new().connect("sqlite::memory:").await.unwrap()
    }

    async fn get_initialized_db() -> Pool {
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        sql_pool
    }

    async fn insert_user(handler: &SqlBackendHandler, name: &str, pass: &str) {
        use crate::domain::opaque_handler::OpaqueHandler;
        insert_user_no_password(handler, name).await;
        let mut rng = rand::rngs::OsRng;
        let client_registration_start =
            opaque::client::registration::start_registration(pass, &mut rng).unwrap();
        let response = handler
            .registration_start(registration::ClientRegistrationStartRequest {
                username: name.to_string(),
                registration_start_request: client_registration_start.message,
            })
            .await
            .unwrap();
        let registration_upload = opaque::client::registration::finish_registration(
            client_registration_start.state,
            response.registration_response,
            &mut rng,
        )
        .unwrap();
        handler
            .registration_finish(registration::ClientRegistrationFinishRequest {
                server_data: response.server_data,
                registration_upload: registration_upload.message,
            })
            .await
            .unwrap();
    }

    async fn insert_user_no_password(handler: &SqlBackendHandler, name: &str) {
        handler
            .create_user(CreateUserRequest {
                user_id: name.to_string(),
                email: "bob@bob.bob".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    async fn insert_group(handler: &SqlBackendHandler, name: &str) -> i32 {
        handler
            .create_group(CreateGroupRequest {
                display_name: name.to_string(),
            })
            .await
            .unwrap()
    }

    async fn insert_membership(handler: &SqlBackendHandler, group_id: i32, user_id: &str) {
        handler
            .add_user_to_group(AddUserToGroupRequest {
                user_id: user_id.to_string(),
                group_id,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_bind_admin() {
        let sql_pool = get_in_memory_db().await;
        let config = ConfigurationBuilder::default()
            .ldap_user_dn("admin".to_string())
            .ldap_user_pass("test".to_string())
            .build()
            .unwrap();
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
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool.clone());
        insert_user(&handler, "bob", "bob00").await;

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
    async fn test_user_no_password() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool.clone());
        insert_user_no_password(&handler, "bob").await;

        handler
            .bind(BindRequest {
                name: "bob".to_string(),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn test_list_users() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool);
        insert_user(&handler, "bob", "bob00").await;
        insert_user(&handler, "patrick", "pass").await;
        insert_user(&handler, "John", "Pa33w0rd!").await;
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
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool.clone());
        insert_user(&handler, "bob", "bob00").await;
        insert_user(&handler, "patrick", "pass").await;
        insert_user(&handler, "John", "Pa33w0rd!").await;
        let group_1 = insert_group(&handler, "Best Group").await;
        let group_2 = insert_group(&handler, "Worst Group").await;
        insert_membership(&handler, group_1, "bob").await;
        insert_membership(&handler, group_1, "patrick").await;
        insert_membership(&handler, group_2, "patrick").await;
        insert_membership(&handler, group_2, "John").await;
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
    async fn test_get_user_details() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool);
        insert_user(&handler, "bob", "bob00").await;
        {
            let user = handler
                .get_user_details(UserDetailsRequest {
                    user_id: String::from("bob"),
                })
                .await
                .unwrap();
            assert_eq!(user.user_id, "bob".to_string());
        }
        {
            handler
                .get_user_details(UserDetailsRequest {
                    user_id: String::from("John"),
                })
                .await
                .unwrap_err();
        }
    }
    #[tokio::test]
    async fn test_get_user_groups() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool.clone());
        insert_user(&handler, "bob", "bob00").await;
        insert_user(&handler, "patrick", "pass").await;
        insert_user(&handler, "John", "Pa33w0rd!").await;
        let group_1 = insert_group(&handler, "Group1").await;
        let group_2 = insert_group(&handler, "Group2").await;
        insert_membership(&handler, group_1, "bob").await;
        insert_membership(&handler, group_1, "patrick").await;
        insert_membership(&handler, group_2, "patrick").await;
        let mut bob_groups = HashSet::new();
        bob_groups.insert("Group1".to_string());
        let mut patrick_groups = HashSet::new();
        patrick_groups.insert("Group1".to_string());
        patrick_groups.insert("Group2".to_string());
        assert_eq!(handler.get_user_groups("bob").await.unwrap(), bob_groups);
        assert_eq!(
            handler.get_user_groups("patrick").await.unwrap(),
            patrick_groups
        );
        assert_eq!(
            handler.get_user_groups("John").await.unwrap(),
            HashSet::new()
        );
    }

    #[tokio::test]
    async fn test_delete_user() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool.clone());

        insert_user(&handler, "val", "s3np4i").await;
        insert_user(&handler, "Hector", "Be$t").await;
        insert_user(&handler, "Jennz", "boupBoup").await;

        // Remove a user
        let _request_result = handler
            .delete_user(DeleteUserRequest {
                user_id: "Jennz".to_owned(),
            })
            .await
            .unwrap();

        let users = handler
            .list_users(ListUsersRequest { filters: None })
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.user_id)
            .collect::<Vec<_>>();

        assert_eq!(users, vec!["Hector", "val"]);

        // Insert new user and remove two
        insert_user(&handler, "NewBoi", "Joni").await;
        let _request_result = handler
            .delete_user(DeleteUserRequest {
                user_id: "Hector".to_owned(),
            })
            .await
            .unwrap();
        let _request_result = handler
            .delete_user(DeleteUserRequest {
                user_id: "NewBoi".to_owned(),
            })
            .await
            .unwrap();

        let users = handler
            .list_users(ListUsersRequest { filters: None })
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.user_id)
            .collect::<Vec<_>>();

        assert_eq!(users, vec!["val"]);
    }
}
