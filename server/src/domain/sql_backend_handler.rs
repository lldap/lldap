use super::{error::*, handler::*, sql_tables::*};
use crate::infra::configuration::Configuration;
use async_trait::async_trait;
use futures_util::StreamExt;
use sea_query::{Alias, Cond, Expr, Iden, Order, Query};
use sea_query_binder::SqlxBinder;
use sqlx::{query_as_with, query_with, FromRow, Row};
use std::collections::HashSet;
use tracing::{debug, instrument};

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
fn get_user_filter_expr(filter: UserRequestFilter) -> (RequiresGroup, Cond) {
    use sea_query::IntoCondition;
    use UserRequestFilter::*;
    fn get_repeated_filter(fs: Vec<UserRequestFilter>, condition: Cond) -> (RequiresGroup, Cond) {
        let mut requires_group = false;
        let filter = fs.into_iter().fold(condition, |c, f| {
            let (group, filters) = get_user_filter_expr(f);
            requires_group |= group.0;
            c.add(filters)
        });
        (RequiresGroup(requires_group), filter)
    }
    match filter {
        And(fs) => get_repeated_filter(fs, Cond::all()),
        Or(fs) => get_repeated_filter(fs, Cond::any()),
        Not(f) => {
            let (requires_group, filters) = get_user_filter_expr(*f);
            (requires_group, filters.not())
        }
        UserId(user_id) => (
            RequiresGroup(false),
            Expr::col((Users::Table, Users::UserId))
                .eq(user_id)
                .into_condition(),
        ),
        Equality(s1, s2) => (
            RequiresGroup(false),
            if s1 == Users::DisplayName.to_string() {
                Expr::col((Users::Table, Users::DisplayName))
                    .eq(s2)
                    .into_condition()
            } else if s1 == Users::UserId.to_string() {
                panic!("User id should be wrapped")
            } else {
                Expr::expr(Expr::cust(&s1)).eq(s2).into_condition()
            },
        ),
        MemberOf(group) => (
            RequiresGroup(true),
            Expr::col((Groups::Table, Groups::DisplayName))
                .eq(group)
                .into_condition(),
        ),
        MemberOfId(group_id) => (
            RequiresGroup(true),
            Expr::col((Groups::Table, Groups::GroupId))
                .eq(group_id)
                .into_condition(),
        ),
    }
}

// Returns the condition for the SQL query, and whether it requires joining with the groups table.
fn get_group_filter_expr(filter: GroupRequestFilter) -> Cond {
    use sea_query::IntoCondition;
    use GroupRequestFilter::*;
    match filter {
        And(fs) => fs
            .into_iter()
            .fold(Cond::all(), |c, f| c.add(get_group_filter_expr(f))),
        Or(fs) => fs
            .into_iter()
            .fold(Cond::any(), |c, f| c.add(get_group_filter_expr(f))),
        Not(f) => get_group_filter_expr(*f).not(),
        DisplayName(name) => Expr::col((Groups::Table, Groups::DisplayName))
            .eq(name)
            .into_condition(),
        GroupId(id) => Expr::col((Groups::Table, Groups::GroupId))
            .eq(id.0)
            .into_condition(),
        Uuid(uuid) => Expr::col((Groups::Table, Groups::Uuid))
            .eq(uuid.to_string())
            .into_condition(),
        // WHERE (group_id in (SELECT group_id FROM memberships WHERE user_id = user))
        Member(user) => Expr::col((Memberships::Table, Memberships::GroupId))
            .in_subquery(
                Query::select()
                    .column(Memberships::GroupId)
                    .from(Memberships::Table)
                    .cond_where(Expr::col(Memberships::UserId).eq(user))
                    .take(),
            )
            .into_condition(),
    }
}

#[async_trait]
impl BackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", ret, err)]
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        debug!(?filters, get_groups);
        let (query, values) = {
            let mut query_builder = Query::select()
                .column((Users::Table, Users::UserId))
                .column(Users::Email)
                .column((Users::Table, Users::DisplayName))
                .column(Users::FirstName)
                .column(Users::LastName)
                .column(Users::Avatar)
                .column((Users::Table, Users::CreationDate))
                .column((Users::Table, Users::Uuid))
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
                    .expr_as(
                        Expr::col((Groups::Table, Groups::DisplayName)),
                        Alias::new("group_display_name"),
                    )
                    .expr_as(
                        Expr::col((Groups::Table, Groups::CreationDate)),
                        sea_query::Alias::new("group_creation_date"),
                    )
                    .expr_as(
                        Expr::col((Groups::Table, Groups::Uuid)),
                        sea_query::Alias::new("group_uuid"),
                    )
                    .order_by(Alias::new("group_display_name"), Order::Asc);
            }
            if let Some(filter) = filters {
                if filter == UserRequestFilter::Not(Box::new(UserRequestFilter::And(Vec::new()))) {
                    return Ok(Vec::new());
                }
                if filter != UserRequestFilter::And(Vec::new())
                    && filter != UserRequestFilter::Or(Vec::new())
                {
                    let (RequiresGroup(requires_group), condition) = get_user_filter_expr(filter);
                    query_builder.cond_where(condition);
                    if requires_group && !get_groups {
                        add_join_group_tables(&mut query_builder);
                    }
                }
            }

            query_builder.build_sqlx(DbQueryBuilder {})
        };

        debug!(%query);

        // For group_by.
        use itertools::Itertools;
        let mut users = Vec::new();
        // The rows are returned sorted by user_id. We group them by
        // this key which gives us one element (`rows`) per group.
        for (_, rows) in &query_with(&query, values)
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
                        rows.filter_map(|row| {
                            let display_name = row.get::<String, _>("group_display_name");
                            if display_name.is_empty() {
                                None
                            } else {
                                Some(GroupDetails {
                                    group_id: row.get::<GroupId, _>(&*Groups::GroupId.to_string()),
                                    display_name,
                                    creation_date: row.get::<chrono::DateTime<chrono::Utc>, _>(
                                        "group_creation_date",
                                    ),
                                    uuid: row.get::<Uuid, _>("group_uuid"),
                                })
                            }
                        })
                        .collect(),
                    )
                } else {
                    None
                },
            });
        }
        Ok(users)
    }

    #[instrument(skip_all, level = "debug", ret, err)]
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        debug!(?filters);
        let (query, values) = {
            let mut query_builder = Query::select()
                .column((Groups::Table, Groups::GroupId))
                .column(Groups::DisplayName)
                .column(Groups::CreationDate)
                .column(Groups::Uuid)
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
                    query_builder.cond_where(get_group_filter_expr(filter));
                }
            }

            query_builder.build_sqlx(DbQueryBuilder {})
        };
        debug!(%query);

        // For group_by.
        use itertools::Itertools;
        let mut groups = Vec::new();
        // The rows are returned sorted by display_name, equivalent to group_id. We group them by
        // this key which gives us one element (`rows`) per group.
        for (group_details, rows) in &query_with(&query, values)
            .fetch_all(&self.sql_pool)
            .await?
            .into_iter()
            .group_by(|row| GroupDetails::from_row(row).unwrap())
        {
            groups.push(Group {
                id: group_details.group_id,
                display_name: group_details.display_name,
                creation_date: group_details.creation_date,
                uuid: group_details.uuid,
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

    #[instrument(skip_all, level = "debug", ret, err)]
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        debug!(?user_id);
        let (query, values) = Query::select()
            .column(Users::UserId)
            .column(Users::Email)
            .column(Users::DisplayName)
            .column(Users::FirstName)
            .column(Users::LastName)
            .column(Users::Avatar)
            .column(Users::CreationDate)
            .column(Users::Uuid)
            .from(Users::Table)
            .cond_where(Expr::col(Users::UserId).eq(user_id))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);

        Ok(query_as_with::<_, User, _>(query.as_str(), values)
            .fetch_one(&self.sql_pool)
            .await?)
    }

    #[instrument(skip_all, level = "debug", ret, err)]
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails> {
        debug!(?group_id);
        let (query, values) = Query::select()
            .column(Groups::GroupId)
            .column(Groups::DisplayName)
            .column(Groups::CreationDate)
            .column(Groups::Uuid)
            .from(Groups::Table)
            .cond_where(Expr::col(Groups::GroupId).eq(group_id))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);

        Ok(query_as_with::<_, GroupDetails, _>(&query, values)
            .fetch_one(&self.sql_pool)
            .await?)
    }

    #[instrument(skip_all, level = "debug", ret, err)]
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        debug!(?user_id);
        let (query, values) = Query::select()
            .column((Groups::Table, Groups::GroupId))
            .column(Groups::DisplayName)
            .column(Groups::CreationDate)
            .column(Groups::Uuid)
            .from(Groups::Table)
            .inner_join(
                Memberships::Table,
                Expr::tbl(Groups::Table, Groups::GroupId)
                    .equals(Memberships::Table, Memberships::GroupId),
            )
            .cond_where(Expr::col(Memberships::UserId).eq(user_id))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);

        query_as_with::<_, GroupDetails, _>(&query, values)
            .fetch(&self.sql_pool)
            // Collect the vector of rows, each potentially an error.
            .collect::<Vec<sqlx::Result<GroupDetails>>>()
            .await
            .into_iter()
            // Transform it into a single result (the first error if any), and group the group_ids
            // into a HashSet.
            .collect::<sqlx::Result<HashSet<_>>>()
            // Map the sqlx::Error into a DomainError.
            .map_err(DomainError::DatabaseError)
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        debug!(user_id = ?request.user_id);
        let columns = vec![
            Users::UserId,
            Users::Email,
            Users::DisplayName,
            Users::FirstName,
            Users::LastName,
            Users::Avatar,
            Users::CreationDate,
            Users::Uuid,
        ];
        let now = chrono::Utc::now();
        let uuid = Uuid::from_name_and_date(request.user_id.as_str(), &now);
        let values = vec![
            request.user_id.into(),
            request.email.into(),
            request.display_name.unwrap_or_default().into(),
            request.first_name.unwrap_or_default().into(),
            request.last_name.unwrap_or_default().into(),
            request.avatar.unwrap_or_default().into(),
            now.naive_utc().into(),
            uuid.into(),
        ];
        let (query, values) = Query::insert()
            .into_table(Users::Table)
            .columns(columns)
            .values_panic(values)
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        query_with(query.as_str(), values)
            .execute(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        debug!(user_id = ?request.user_id);
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
        if let Some(avatar) = request.avatar {
            values.push((Users::Avatar, avatar.into()));
        }
        if values.is_empty() {
            return Ok(());
        }
        let (query, values) = Query::update()
            .table(Users::Table)
            .values(values)
            .cond_where(Expr::col(Users::UserId).eq(request.user_id))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        query_with(query.as_str(), values)
            .execute(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        debug!(?request.group_id);
        let mut values = Vec::new();
        if let Some(display_name) = request.display_name {
            values.push((Groups::DisplayName, display_name.into()));
        }
        if values.is_empty() {
            return Ok(());
        }
        let (query, values) = Query::update()
            .table(Groups::Table)
            .values(values)
            .cond_where(Expr::col(Groups::GroupId).eq(request.group_id))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        query_with(query.as_str(), values)
            .execute(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        debug!(?user_id);
        let (query, values) = Query::delete()
            .from_table(Users::Table)
            .cond_where(Expr::col(Users::UserId).eq(user_id))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        query_with(query.as_str(), values)
            .execute(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", ret, err)]
    async fn create_group(&self, group_name: &str) -> Result<GroupId> {
        debug!(?group_name);
        crate::domain::sql_tables::create_group(group_name, &self.sql_pool).await?;
        let (query, values) = Query::select()
            .column(Groups::GroupId)
            .from(Groups::Table)
            .cond_where(Expr::col(Groups::DisplayName).eq(group_name))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        let row = query_with(query.as_str(), values)
            .fetch_one(&self.sql_pool)
            .await?;
        Ok(GroupId(row.get::<i32, _>(&*Groups::GroupId.to_string())))
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        debug!(?group_id);
        let (query, values) = Query::delete()
            .from_table(Groups::Table)
            .cond_where(Expr::col(Groups::GroupId).eq(group_id))
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        query_with(query.as_str(), values)
            .execute(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        debug!(?user_id, ?group_id);
        let (query, values) = Query::insert()
            .into_table(Memberships::Table)
            .columns(vec![Memberships::UserId, Memberships::GroupId])
            .values_panic(vec![user_id.into(), group_id.into()])
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        query_with(query.as_str(), values)
            .execute(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        debug!(?user_id, ?group_id);
        let (query, values) = Query::delete()
            .from_table(Memberships::Table)
            .cond_where(
                Cond::all()
                    .add(Expr::col(Memberships::GroupId).eq(group_id))
                    .add(Expr::col(Memberships::UserId).eq(user_id)),
            )
            .build_sqlx(DbQueryBuilder {});
        debug!(%query);
        query_with(query.as_str(), values)
            .execute(&self.sql_pool)
            .await?;
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
        ConfigurationBuilder::for_tests()
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
        insert_user(&handler, "NoGroup", "Pa33w0rd!").await;
        let group_1 = insert_group(&handler, "Best Group").await;
        let group_2 = insert_group(&handler, "Worst Group").await;
        insert_membership(&handler, group_1, "bob").await;
        insert_membership(&handler, group_1, "patrick").await;
        insert_membership(&handler, group_2, "patrick").await;
        insert_membership(&handler, group_2, "John").await;
        {
            let users = get_user_names(&handler, None).await;
            assert_eq!(users, vec!["bob", "john", "nogroup", "patrick"]);
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
                Some(UserRequestFilter::And(vec![
                    UserRequestFilter::Or(vec![]),
                    UserRequestFilter::Or(vec![
                        UserRequestFilter::UserId(UserId::new("bob")),
                        UserRequestFilter::UserId(UserId::new("John")),
                        UserRequestFilter::UserId(UserId::new("random")),
                    ]),
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
            assert_eq!(users, vec!["john", "nogroup", "patrick"]);
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
                        u.user.display_name.to_string(),
                        u.groups
                            .unwrap()
                            .into_iter()
                            .map(|g| g.group_id)
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                users,
                vec![
                    ("bob".to_string(), String::new(), vec![group_1]),
                    ("john".to_string(), String::new(), vec![group_2]),
                    ("nogroup".to_string(), String::new(), vec![]),
                    ("patrick".to_string(), String::new(), vec![group_1, group_2]),
                ]
            );
        }
        {
            let users = handler
                .list_users(None, true)
                .await
                .unwrap()
                .into_iter()
                .map(|u| {
                    (
                        u.user.creation_date,
                        u.groups
                            .unwrap()
                            .into_iter()
                            .map(|g| g.creation_date)
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            for (user_date, groups) in users {
                for group_date in groups {
                    assert_ne!(user_date, group_date);
                }
            }
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
        let get_group_ids = |filter| async {
            handler
                .list_groups(filter)
                .await
                .unwrap()
                .into_iter()
                .map(|g| g.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(get_group_ids(None).await, vec![group_1, group_3, group_2]);
        assert_eq!(
            get_group_ids(Some(GroupRequestFilter::Or(vec![
                GroupRequestFilter::DisplayName("Empty Group".to_string()),
                GroupRequestFilter::Member(UserId::new("bob")),
            ])))
            .await,
            vec![group_1, group_3]
        );
        assert_eq!(
            get_group_ids(Some(GroupRequestFilter::And(vec![
                GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                    "value".to_string()
                ))),
                GroupRequestFilter::GroupId(group_1),
            ])))
            .await,
            vec![group_1]
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
        let get_group_ids = |user: &'static str| async {
            let mut groups = handler
                .get_user_groups(&UserId::new(user))
                .await
                .unwrap()
                .into_iter()
                .map(|g| g.group_id)
                .collect::<Vec<_>>();
            groups.sort_by(|g1, g2| g1.0.cmp(&g2.0));
            groups
        };
        assert_eq!(get_group_ids("bob").await, vec![group_1]);
        assert_eq!(get_group_ids("patrick").await, vec![group_1, group_2]);
        assert_eq!(get_group_ids("John").await, vec![]);
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
        handler.delete_user(&UserId::new("Jennz")).await.unwrap();

        assert_eq!(get_user_names(&handler, None).await, vec!["hector", "val"]);

        // Insert new user and remove two
        insert_user(&handler, "NewBoi", "Joni").await;
        handler.delete_user(&UserId::new("Hector")).await.unwrap();
        handler.delete_user(&UserId::new("NewBoi")).await.unwrap();

        assert_eq!(get_user_names(&handler, None).await, vec!["val"]);
    }

    #[tokio::test]
    async fn test_sql_injection() {
        let sql_pool = get_initialized_db().await;
        let config = get_default_config();
        let handler = SqlBackendHandler::new(config, sql_pool);
        let user_name = UserId::new(r#"bob"e"i'o;aü"#);
        insert_user(&handler, user_name.as_str(), "bob00").await;
        {
            let users = handler
                .list_users(None, false)
                .await
                .unwrap()
                .into_iter()
                .map(|u| u.user.user_id)
                .collect::<Vec<_>>();

            assert_eq!(users, vec![user_name.clone()]);
            let user = handler.get_user_details(&user_name).await.unwrap();
            assert_eq!(user.user_id, user_name);
        }
    }
}
