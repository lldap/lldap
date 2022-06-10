use super::{error::*, handler::*, sql_tables::*};
use crate::infra::configuration::Configuration;
use async_trait::async_trait;
use futures_util::StreamExt;
use sea_query::{Expr, Iden, Order, Query, SimpleExpr};
use sqlx::{FromRow, Row};
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

struct RequiresGroup(bool);

// Returns the condition for the SQL query, and whether it requires joining with the groups table.
fn get_user_filter_expr(filter: UserRequestFilter) -> (RequiresGroup, SimpleExpr) {
    use UserRequestFilter::*;
    fn get_repeated_filter(
        fs: Vec<UserRequestFilter>,
        field: &dyn Fn(SimpleExpr, SimpleExpr) -> SimpleExpr,
    ) -> (RequiresGroup, SimpleExpr) {
        let mut requires_group = false;
        let mut it = fs.into_iter();
        let first_expr = match it.next() {
            None => return (RequiresGroup(false), Expr::value(true)),
            Some(f) => {
                let (group, filter) = get_user_filter_expr(f);
                requires_group |= group.0;
                filter
            }
        };
        let filter = it.fold(first_expr, |e, f| {
            let (group, filters) = get_user_filter_expr(f);
            requires_group |= group.0;
            field(e, filters)
        });
        (RequiresGroup(requires_group), filter)
    }
    match filter {
        And(fs) => get_repeated_filter(fs, &SimpleExpr::and),
        Or(fs) => get_repeated_filter(fs, &SimpleExpr::or),
        Not(f) => {
            let (requires_group, filters) = get_user_filter_expr(*f);
            (requires_group, Expr::not(Expr::expr(filters)))
        }
        UserId(user_id) => (
            RequiresGroup(false),
            Expr::col((Users::Table, Users::UserId)).eq(user_id),
        ),
        Equality(s1, s2) => (
            RequiresGroup(false),
            if s1 == Users::DisplayName.to_string() {
                Expr::col((Users::Table, Users::DisplayName)).eq(s2)
            } else if s1 == Users::UserId.to_string() {
                panic!("User id should be wrapped")
            } else {
                Expr::expr(Expr::cust(&s1)).eq(s2)
            },
        ),
        MemberOf(group) => (
            RequiresGroup(true),
            Expr::col((Groups::Table, Groups::DisplayName)).eq(group),
        ),
        MemberOfId(group_id) => (
            RequiresGroup(true),
            Expr::col((Groups::Table, Groups::GroupId)).eq(group_id),
        ),
    }
}

// Returns the condition for the SQL query, and whether it requires joining with the groups table.
fn get_group_filter_expr(filter: GroupRequestFilter) -> SimpleExpr {
    use GroupRequestFilter::*;
    fn get_repeated_filter(
        fs: Vec<GroupRequestFilter>,
        field: &dyn Fn(SimpleExpr, SimpleExpr) -> SimpleExpr,
    ) -> SimpleExpr {
        let mut it = fs.into_iter();
        let first_expr = match it.next() {
            None => return Expr::value(true),
            Some(f) => get_group_filter_expr(f),
        };
        it.fold(first_expr, |e, f| field(e, get_group_filter_expr(f)))
    }
    match filter {
        And(fs) => get_repeated_filter(fs, &SimpleExpr::and),
        Or(fs) => get_repeated_filter(fs, &SimpleExpr::or),
        Not(f) => Expr::not(Expr::expr(get_group_filter_expr(*f))),
        DisplayName(name) => Expr::col((Groups::Table, Groups::DisplayName)).eq(name),
        GroupId(id) => Expr::col((Groups::Table, Groups::GroupId)).eq(id.0),
        // WHERE (group_id in (SELECT group_id FROM memberships WHERE user_id = user))
        Member(user) => Expr::col((Memberships::Table, Memberships::GroupId)).in_subquery(
            Query::select()
                .column(Memberships::GroupId)
                .from(Memberships::Table)
                .and_where(Expr::col(Memberships::UserId).eq(user))
                .take(),
        ),
    }
}

#[async_trait]
impl BackendHandler for SqlBackendHandler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        let query = {
            let mut query_builder = Query::select()
                .column((Users::Table, Users::UserId))
                .column(Users::Email)
                .column((Users::Table, Users::DisplayName))
                .column(Users::FirstName)
                .column(Users::LastName)
                .column(Users::Avatar)
                .column(Users::CreationDate)
                .from(Users::Table)
                .order_by((Users::Table, Users::UserId), Order::Asc)
                .to_owned();
            let add_join_group_tables = |builder: &mut sea_query::SelectStatement| {
                builder
                    .left_join(
                        Memberships::Table,
                        Expr::tbl(Users::Table, Users::UserId)
                            .equals(Memberships::Table, Memberships::UserId),
                    )
                    .left_join(
                        Groups::Table,
                        Expr::tbl(Memberships::Table, Memberships::GroupId)
                            .equals(Groups::Table, Groups::GroupId),
                    );
            };
            if get_groups {
                add_join_group_tables(&mut query_builder);
                query_builder
                    .column((Groups::Table, Groups::GroupId))
                    .column((Groups::Table, Groups::DisplayName))
                    .order_by((Groups::Table, Groups::DisplayName), Order::Asc);
            }
            if let Some(filter) = filters {
                if filter == UserRequestFilter::Not(Box::new(UserRequestFilter::And(Vec::new()))) {
                    return Ok(Vec::new());
                }
                if filter != UserRequestFilter::And(Vec::new())
                    && filter != UserRequestFilter::Or(Vec::new())
                {
                    let (RequiresGroup(requires_group), condition) = get_user_filter_expr(filter);
                    query_builder.and_where(condition);
                    if requires_group && !get_groups {
                        add_join_group_tables(&mut query_builder);
                    }
                }
            }

            query_builder.to_string(DbQueryBuilder {})
        };

        // For group_by.
        use itertools::Itertools;
        let mut users = Vec::new();
        // The rows are returned sorted by user_id. We group them by
        // this key which gives us one element (`rows`) per group.
        for (_, rows) in &sqlx::query(&query)
            .fetch_all(&self.sql_pool)
            .await?
            .into_iter()
            .group_by(|row| row.get::<UserId, _>(&*Users::UserId.to_string()))
        {
            let mut rows = rows.peekable();
            users.push(UserAndGroups {
                user: User::from_row(rows.peek().unwrap()).unwrap(),
                groups: if get_groups {
                    Some(
                        rows.map(|row| {
                            GroupIdAndName(
                                GroupId(row.get::<i32, _>(&*Groups::GroupId.to_string())),
                                row.get::<String, _>(&*Groups::DisplayName.to_string()),
                            )
                        })
                        .filter(|g| !g.1.is_empty())
                        .collect(),
                    )
                } else {
                    None
                },
            });
        }

        Ok(users)
    }

    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        let query: String = {
            let mut query_builder = Query::select()
                .column((Groups::Table, Groups::GroupId))
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
                .to_owned();

            if let Some(filter) = filters {
                if filter == GroupRequestFilter::Not(Box::new(GroupRequestFilter::And(Vec::new())))
                {
                    return Ok(Vec::new());
                }
                if filter != GroupRequestFilter::And(Vec::new())
                    && filter != GroupRequestFilter::Or(Vec::new())
                {
                    query_builder.and_where(get_group_filter_expr(filter));
                }
            }

            query_builder.to_string(DbQueryBuilder {})
        };

        // For group_by.
        use itertools::Itertools;
        let mut groups = Vec::new();
        // The rows are returned sorted by display_name, equivalent to group_id. We group them by
        // this key which gives us one element (`rows`) per group.
        for ((group_id, display_name), rows) in &sqlx::query(&query)
            .fetch_all(&self.sql_pool)
            .await?
            .into_iter()
            .group_by(|row| {
                (
                    GroupId(row.get::<i32, _>(&*Groups::GroupId.to_string())),
                    row.get::<String, _>(&*Groups::DisplayName.to_string()),
                )
            })
        {
            groups.push(Group {
                id: group_id,
                display_name,
                users: rows
                    .map(|row| row.get::<UserId, _>(&*Memberships::UserId.to_string()))
                    // If a group has no users, an empty string is returned because of the left
                    // join.
                    .filter(|s| !s.as_str().is_empty())
                    .collect(),
            });
        }
        Ok(groups)
    }

    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        let query = Query::select()
            .column(Users::UserId)
            .column(Users::Email)
            .column(Users::DisplayName)
            .column(Users::FirstName)
            .column(Users::LastName)
            .column(Users::Avatar)
            .column(Users::CreationDate)
            .from(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(user_id))
            .to_string(DbQueryBuilder {});

        Ok(sqlx::query_as::<_, User>(&query)
            .fetch_one(&self.sql_pool)
            .await?)
    }

    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupIdAndName> {
        let query = Query::select()
            .column(Groups::GroupId)
            .column(Groups::DisplayName)
            .from(Groups::Table)
            .and_where(Expr::col(Groups::GroupId).eq(group_id))
            .to_string(DbQueryBuilder {});

        Ok(sqlx::query_as::<_, GroupIdAndName>(&query)
            .fetch_one(&self.sql_pool)
            .await?)
    }

    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupIdAndName>> {
        if *user_id == self.config.ldap_user_dn {
            let mut groups = HashSet::new();
            groups.insert(GroupIdAndName(GroupId(1), "lldap_admin".to_string()));
            return Ok(groups);
        }
        let query: String = Query::select()
            .column((Groups::Table, Groups::GroupId))
            .column(Groups::DisplayName)
            .from(Groups::Table)
            .inner_join(
                Memberships::Table,
                Expr::tbl(Groups::Table, Groups::GroupId)
                    .equals(Memberships::Table, Memberships::GroupId),
            )
            .and_where(Expr::col(Memberships::UserId).eq(user_id))
            .to_string(DbQueryBuilder {});

        sqlx::query(&query)
            // Extract the group id from the row.
            .map(|row: DbRow| {
                GroupIdAndName(
                    row.get::<GroupId, _>(&*Groups::GroupId.to_string()),
                    row.get::<String, _>(&*Groups::DisplayName.to_string()),
                )
            })
            .fetch(&self.sql_pool)
            // Collect the vector of rows, each potentially an error.
            .collect::<Vec<sqlx::Result<GroupIdAndName>>>()
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
            request.user_id.into(),
            request.email.into(),
            request.display_name.unwrap_or_default().into(),
            request.first_name.unwrap_or_default().into(),
            request.last_name.unwrap_or_default().into(),
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

    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        let mut values = Vec::new();
        if let Some(email) = request.email {
            values.push((Users::Email, email.into()));
        }
        if let Some(display_name) = request.display_name {
            values.push((Users::DisplayName, display_name.into()));
        }
        if let Some(first_name) = request.first_name {
            values.push((Users::FirstName, first_name.into()));
        }
        if let Some(last_name) = request.last_name {
            values.push((Users::LastName, last_name.into()));
        }
        if values.is_empty() {
            return Ok(());
        }
        let query = Query::update()
            .table(Users::Table)
            .values(values)
            .and_where(Expr::col(Users::UserId).eq(request.user_id))
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        let mut values = Vec::new();
        if let Some(display_name) = request.display_name {
            values.push((Groups::DisplayName, display_name.into()));
        }
        if values.is_empty() {
            return Ok(());
        }
        let query = Query::update()
            .table(Groups::Table)
            .values(values)
            .and_where(Expr::col(Groups::GroupId).eq(request.group_id))
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        let delete_query = Query::delete()
            .from_table(Users::Table)
            .and_where(Expr::col(Users::UserId).eq(user_id))
            .to_string(DbQueryBuilder {});
        sqlx::query(&delete_query).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn create_group(&self, group_name: &str) -> Result<GroupId> {
        let query = Query::insert()
            .into_table(Groups::Table)
            .columns(vec![Groups::DisplayName])
            .values_panic(vec![group_name.into()])
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        let query = Query::select()
            .column(Groups::GroupId)
            .from(Groups::Table)
            .and_where(Expr::col(Groups::DisplayName).eq(group_name))
            .to_string(DbQueryBuilder {});
        let row = sqlx::query(&query).fetch_one(&self.sql_pool).await?;
        Ok(GroupId(row.get::<i32, _>(&*Groups::GroupId.to_string())))
    }

    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        let delete_query = Query::delete()
            .from_table(Groups::Table)
            .and_where(Expr::col(Groups::GroupId).eq(group_id))
            .to_string(DbQueryBuilder {});
        sqlx::query(&delete_query).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        let query = Query::insert()
            .into_table(Memberships::Table)
            .columns(vec![Memberships::UserId, Memberships::GroupId])
            .values_panic(vec![user_id.into(), group_id.into()])
            .to_string(DbQueryBuilder {});
        sqlx::query(&query).execute(&self.sql_pool).await?;
        Ok(())
    }

    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        let query = Query::delete()
            .from_table(Memberships::Table)
            .and_where(Expr::col(Memberships::GroupId).eq(group_id))
            .and_where(Expr::col(Memberships::UserId).eq(user_id))
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
    use lldap_auth::{opaque, registration};

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
                user_id: UserId::new(name),
                email: "bob@bob.bob".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    async fn insert_group(handler: &SqlBackendHandler, name: &str) -> GroupId {
        handler.create_group(name).await.unwrap()
    }

    async fn insert_membership(handler: &SqlBackendHandler, group_id: GroupId, user_id: &str) {
        handler
            .add_user_to_group(&UserId::new(user_id), group_id)
            .await
            .unwrap();
    }

    async fn get_user_names(
        handler: &SqlBackendHandler,
        filters: Option<UserRequestFilter>,
    ) -> Vec<String> {
        handler
            .list_users(filters, false)
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.user.user_id.to_string())
            .collect::<Vec<_>>()
    }

    #[tokio::test]
    async fn test_bind_admin() {
        let sql_pool = get_in_memory_db().await;
        let config = ConfigurationBuilder::default()
            .ldap_user_dn(UserId::new("admin"))
            .ldap_user_pass(secstr::SecUtf8::from("test"))
            .build()
            .unwrap();
        let handler = SqlBackendHandler::new(config, sql_pool);
        handler
            .bind(BindRequest {
                name: UserId::new("admin"),
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
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap();
        handler
            .bind(BindRequest {
                name: UserId::new("andrew"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
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
                name: UserId::new("bob"),
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
        let group_1 = insert_group(&handler, "Best Group").await;
        let group_2 = insert_group(&handler, "Worst Group").await;
        insert_membership(&handler, group_1, "bob").await;
        insert_membership(&handler, group_1, "patrick").await;
        insert_membership(&handler, group_2, "patrick").await;
        insert_membership(&handler, group_2, "John").await;
        {
            let users = get_user_names(&handler, None).await;
            assert_eq!(users, vec!["bob", "john", "patrick"]);
        }
        {
            let users = get_user_names(
                &handler,
                Some(UserRequestFilter::UserId(UserId::new("bob"))),
            )
            .await;
            assert_eq!(users, vec!["bob"]);
        }
        {
            let users = get_user_names(
                &handler,
                Some(UserRequestFilter::Or(vec![
                    UserRequestFilter::UserId(UserId::new("bob")),
                    UserRequestFilter::UserId(UserId::new("John")),
                ])),
            )
            .await;
            assert_eq!(users, vec!["bob", "john"]);
        }
        {
            let users = get_user_names(
                &handler,
                Some(UserRequestFilter::Not(Box::new(UserRequestFilter::UserId(
                    UserId::new("bob"),
                )))),
            )
            .await;
            assert_eq!(users, vec!["john", "patrick"]);
        }
        {
            let users = handler
                .list_users(None, true)
                .await
                .unwrap()
                .into_iter()
                .map(|u| {
                    (
                        u.user.user_id.to_string(),
                        u.groups
                            .unwrap()
                            .into_iter()
                            .map(|g| g.0)
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                users,
                vec![
                    ("bob".to_string(), vec![group_1]),
                    ("john".to_string(), vec![group_2]),
                    ("patrick".to_string(), vec![group_1, group_2]),
                ]
            );
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
        let group_3 = insert_group(&handler, "Empty Group").await;
        insert_membership(&handler, group_1, "bob").await;
        insert_membership(&handler, group_1, "patrick").await;
        insert_membership(&handler, group_2, "patrick").await;
        insert_membership(&handler, group_2, "John").await;
        assert_eq!(
            handler.list_groups(None).await.unwrap(),
            vec![
                Group {
                    id: group_1,
                    display_name: "Best Group".to_string(),
                    users: vec![UserId::new("bob"), UserId::new("patrick")]
                },
                Group {
                    id: group_3,
                    display_name: "Empty Group".to_string(),
                    users: vec![]
                },
                Group {
                    id: group_2,
                    display_name: "Worst Group".to_string(),
                    users: vec![UserId::new("john"), UserId::new("patrick")]
                },
            ]
        );
        assert_eq!(
            handler
                .list_groups(Some(GroupRequestFilter::Or(vec![
                    GroupRequestFilter::DisplayName("Empty Group".to_string()),
                    GroupRequestFilter::Member(UserId::new("bob")),
                ])))
                .await
                .unwrap(),
            vec![
                Group {
                    id: group_1,
                    display_name: "Best Group".to_string(),
                    users: vec![UserId::new("bob"), UserId::new("patrick")]
                },
                Group {
                    id: group_3,
                    display_name: "Empty Group".to_string(),
                    users: vec![]
                },
            ]
        );
        assert_eq!(
            handler
                .list_groups(Some(GroupRequestFilter::And(vec![
                    GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                        "value".to_string()
                    ))),
                    GroupRequestFilter::GroupId(group_1),
                ])))
                .await
                .unwrap(),
            vec![Group {
                id: group_1,
                display_name: "Best Group".to_string(),
                users: vec![UserId::new("bob"), UserId::new("patrick")]
            }]
        );
    }

    #[tokio::test]
    async fn test_get_user_details() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool);
        insert_user(&handler, "bob", "bob00").await;
        {
            let user = handler.get_user_details(&UserId::new("bob")).await.unwrap();
            assert_eq!(user.user_id.as_str(), "bob");
        }
        {
            handler
                .get_user_details(&UserId::new("John"))
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn test_user_lowercase() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool);
        insert_user(&handler, "Bob", "bob00").await;
        {
            let user = handler.get_user_details(&UserId::new("bOb")).await.unwrap();
            assert_eq!(user.user_id.as_str(), "bob");
        }
        {
            handler
                .get_user_details(&UserId::new("John"))
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
        bob_groups.insert(GroupIdAndName(group_1, "Group1".to_string()));
        let mut patrick_groups = HashSet::new();
        patrick_groups.insert(GroupIdAndName(group_1, "Group1".to_string()));
        patrick_groups.insert(GroupIdAndName(group_2, "Group2".to_string()));
        assert_eq!(
            handler.get_user_groups(&UserId::new("bob")).await.unwrap(),
            bob_groups
        );
        assert_eq!(
            handler
                .get_user_groups(&UserId::new("patrick"))
                .await
                .unwrap(),
            patrick_groups
        );
        assert_eq!(
            handler.get_user_groups(&UserId::new("John")).await.unwrap(),
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
        let _request_result = handler.delete_user(&UserId::new("Jennz")).await.unwrap();

        assert_eq!(get_user_names(&handler, None).await, vec!["hector", "val"]);

        // Insert new user and remove two
        insert_user(&handler, "NewBoi", "Joni").await;
        let _request_result = handler.delete_user(&UserId::new("Hector")).await.unwrap();
        let _request_result = handler.delete_user(&UserId::new("NewBoi")).await.unwrap();

        assert_eq!(get_user_names(&handler, None).await, vec!["val"]);
    }
}
