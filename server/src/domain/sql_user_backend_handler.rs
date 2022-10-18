use super::{
    error::Result,
    handler::{
        CreateUserRequest, GroupDetails, GroupId, UpdateUserRequest, User, UserAndGroups,
        UserBackendHandler, UserId, UserRequestFilter, Uuid,
    },
    sql_backend_handler::SqlBackendHandler,
    sql_tables::{DbQueryBuilder, Groups, Memberships, Users},
};
use async_trait::async_trait;
use sea_query::{Alias, Cond, Expr, Iden, Order, Query, SimpleExpr};
use sea_query_binder::{SqlxBinder, SqlxValues};
use sqlx::{query_as_with, query_with, FromRow, Row};
use std::collections::HashSet;
use tracing::{debug, instrument};

struct RequiresGroup(bool);

// Returns the condition for the SQL query, and whether it requires joining with the groups table.
fn get_user_filter_expr(filter: UserRequestFilter) -> (RequiresGroup, Cond) {
    use sea_query::IntoCondition;
    use UserRequestFilter::*;
    fn get_repeated_filter(
        fs: Vec<UserRequestFilter>,
        condition: Cond,
        default_value: bool,
    ) -> (RequiresGroup, Cond) {
        if fs.is_empty() {
            return (
                RequiresGroup(false),
                SimpleExpr::Value(default_value.into()).into_condition(),
            );
        }
        let mut requires_group = false;
        let filter = fs.into_iter().fold(condition, |c, f| {
            let (group, filters) = get_user_filter_expr(f);
            requires_group |= group.0;
            c.add(filters)
        });
        (RequiresGroup(requires_group), filter)
    }
    match filter {
        And(fs) => get_repeated_filter(fs, Cond::all(), true),
        Or(fs) => get_repeated_filter(fs, Cond::any(), false),
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

fn get_list_users_query(
    filters: Option<UserRequestFilter>,
    get_groups: bool,
) -> (String, SqlxValues) {
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
        let (RequiresGroup(requires_group), condition) = get_user_filter_expr(filter);
        query_builder.cond_where(condition);
        if requires_group && !get_groups {
            add_join_group_tables(&mut query_builder);
        }
    }

    query_builder.build_sqlx(DbQueryBuilder {})
}

#[async_trait]
impl UserBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", ret, err)]
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        debug!(?filters, get_groups);
        let (query, values) = get_list_users_query(filters, get_groups);

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

    #[instrument(skip_all, level = "debug", ret)]
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

        Ok(HashSet::from_iter(
            query_as_with::<_, GroupDetails, _>(&query, values)
                .fetch_all(&self.sql_pool)
                .await?,
        ))
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
    use crate::domain::{handler::JpegPhoto, sql_backend_handler::tests::*};

    #[tokio::test]
    async fn test_list_users_no_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(&fixture.handler, None).await;
        assert_eq!(users, vec!["bob", "john", "nogroup", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_user_id_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::UserId(UserId::new("bob"))),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_display_name_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Equality(
                "display_name".to_string(),
                "display bob".to_string(),
            )),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_other_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Equality(
                "first_name".to_string(),
                "first bob".to_string(),
            )),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_false_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Not(Box::new(UserRequestFilter::And(
                vec![],
            )))),
        )
        .await;
        assert_eq!(users, Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_list_users_member_of() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::MemberOf("Best Group".to_string())),
        )
        .await;
        assert_eq!(users, vec!["bob", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_member_of_id() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::MemberOfId(fixture.groups[0])),
        )
        .await;
        assert_eq!(users, vec!["bob", "patrick"]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_list_users_invalid_userid_filter() {
        let fixture = TestFixture::new().await;
        get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Equality(
                "user_id".to_string(),
                "first bob".to_string(),
            )),
        )
        .await;
    }

    #[tokio::test]
    async fn test_list_users_filter_or() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::UserId(UserId::new("bob")),
                UserRequestFilter::UserId(UserId::new("John")),
            ])),
        )
        .await;
        assert_eq!(users, vec!["bob", "john"]);
    }

    #[tokio::test]
    async fn test_list_users_filter_many_or() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Or(vec![
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

    #[tokio::test]
    async fn test_list_users_filter_not() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Not(Box::new(UserRequestFilter::UserId(
                UserId::new("bob"),
            )))),
        )
        .await;
        assert_eq!(users, vec!["john", "nogroup", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_with_groups() {
        let fixture = TestFixture::new().await;
        let users = fixture
            .handler
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
                (
                    "bob".to_string(),
                    "display bob".to_string(),
                    vec![fixture.groups[0]]
                ),
                (
                    "john".to_string(),
                    "display John".to_string(),
                    vec![fixture.groups[1]]
                ),
                ("nogroup".to_string(), "display NoGroup".to_string(), vec![]),
                (
                    "patrick".to_string(),
                    "display patrick".to_string(),
                    vec![fixture.groups[0], fixture.groups[1]]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_users_groups_have_different_creation_date_than_users() {
        let fixture = TestFixture::new().await;
        let users = fixture
            .handler
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

    #[tokio::test]
    async fn test_get_user_details() {
        let handler = SqlBackendHandler::new(get_default_config(), get_initialized_db().await);
        insert_user_no_password(&handler, "bob").await;
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
        let handler = SqlBackendHandler::new(get_default_config(), get_initialized_db().await);
        insert_user_no_password(&handler, "Bob").await;
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
    async fn test_delete_user() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .delete_user(&UserId::new("bob"))
            .await
            .unwrap();

        assert_eq!(
            get_user_names(&fixture.handler, None).await,
            vec!["john", "nogroup", "patrick"]
        );

        // Insert new user and remove two
        insert_user_no_password(&fixture.handler, "NewBoi").await;
        fixture
            .handler
            .delete_user(&UserId::new("nogroup"))
            .await
            .unwrap();
        fixture
            .handler
            .delete_user(&UserId::new("NewBoi"))
            .await
            .unwrap();

        assert_eq!(
            get_user_names(&fixture.handler, None).await,
            vec!["john", "patrick"]
        );
    }

    #[tokio::test]
    async fn test_get_user_groups() {
        let fixture = TestFixture::new().await;
        let get_group_ids = |user: &'static str| async {
            let mut groups = fixture
                .handler
                .get_user_groups(&UserId::new(user))
                .await
                .unwrap()
                .into_iter()
                .map(|g| g.group_id)
                .collect::<Vec<_>>();
            groups.sort_by(|g1, g2| g1.0.cmp(&g2.0));
            groups
        };
        assert_eq!(get_group_ids("bob").await, vec![fixture.groups[0]]);
        assert_eq!(
            get_group_ids("patrick").await,
            vec![fixture.groups[0], fixture.groups[1]]
        );
        assert_eq!(get_group_ids("nogroup").await, vec![]);
    }

    #[tokio::test]
    async fn test_update_user_all_values() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                email: Some("email".to_string()),
                display_name: Some("display_name".to_string()),
                first_name: Some("first_name".to_string()),
                last_name: Some("last_name".to_string()),
                avatar: Some(JpegPhoto::default()),
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(user.email, "email");
        assert_eq!(user.display_name, "display_name");
        assert_eq!(user.first_name, "first_name");
        assert_eq!(user.last_name, "last_name");
        assert_eq!(user.avatar, JpegPhoto::default());
    }

    #[tokio::test]
    async fn test_update_user_some_values() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                first_name: Some("first_name".to_string()),
                last_name: Some(String::new()),
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(user.display_name, "display bob");
        assert_eq!(user.first_name, "first_name");
        assert_eq!(user.last_name, "");
    }

    #[tokio::test]
    async fn test_remove_user_from_group() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .remove_user_from_group(&UserId::new("bob"), fixture.groups[0])
            .await
            .unwrap();

        assert_eq!(
            get_user_names(
                &fixture.handler,
                Some(UserRequestFilter::MemberOfId(fixture.groups[0])),
            )
            .await,
            vec!["patrick"]
        );
    }
}
