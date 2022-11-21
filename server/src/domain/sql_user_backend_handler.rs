use super::{
    error::{DomainError, Result},
    handler::{
        CreateUserRequest, GroupDetails, GroupId, UpdateUserRequest, User, UserAndGroups,
        UserBackendHandler, UserId, UserRequestFilter, Uuid,
    },
    model::{self, GroupColumn, UserColumn},
    sql_backend_handler::SqlBackendHandler,
};
use async_trait::async_trait;
use sea_orm::{
    entity::IntoActiveValue,
    sea_query::{Cond, Expr, IntoCondition, SimpleExpr},
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, Set,
};
use sea_query::{Alias, IntoColumnRef};
use std::collections::HashSet;
use tracing::{debug, instrument};

fn get_user_filter_expr(filter: UserRequestFilter) -> Cond {
    use UserRequestFilter::*;
    let group_table = Alias::new("r1");
    fn get_repeated_filter(
        fs: Vec<UserRequestFilter>,
        condition: Cond,
        default_value: bool,
    ) -> Cond {
        if fs.is_empty() {
            SimpleExpr::Value(default_value.into()).into_condition()
        } else {
            fs.into_iter()
                .map(get_user_filter_expr)
                .fold(condition, Cond::add)
        }
    }
    match filter {
        And(fs) => get_repeated_filter(fs, Cond::all(), true),
        Or(fs) => get_repeated_filter(fs, Cond::any(), false),
        Not(f) => get_user_filter_expr(*f).not(),
        UserId(user_id) => ColumnTrait::eq(&UserColumn::UserId, user_id).into_condition(),
        Equality(s1, s2) => {
            if s1 == UserColumn::UserId {
                panic!("User id should be wrapped")
            } else {
                ColumnTrait::eq(&s1, s2).into_condition()
            }
        }
        MemberOf(group) => Expr::col((group_table, GroupColumn::DisplayName))
            .eq(group)
            .into_condition(),
        MemberOfId(group_id) => Expr::col((group_table, GroupColumn::GroupId))
            .eq(group_id)
            .into_condition(),
    }
}
fn to_value(opt_name: &Option<String>) -> ActiveValue<Option<String>> {
    match opt_name {
        None => ActiveValue::NotSet,
        Some(name) => ActiveValue::Set(if name.is_empty() {
            None
        } else {
            Some(name.to_owned())
        }),
    }
}

#[async_trait]
impl UserBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", ret, err)]
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        debug!(?filters);
        let query = model::User::find()
            .filter(
                filters
                    .map(|f| {
                        UserColumn::UserId
                            .in_subquery(
                                model::User::find()
                                    .find_also_linked(model::memberships::UserToGroup)
                                    .select_only()
                                    .column(UserColumn::UserId)
                                    .filter(get_user_filter_expr(f))
                                    .into_query(),
                            )
                            .into_condition()
                    })
                    .unwrap_or_else(|| SimpleExpr::Value(true.into()).into_condition()),
            )
            .order_by_asc(UserColumn::UserId);
        if !get_groups {
            Ok(query
                .into_model::<User>()
                .all(&self.sql_pool)
                .await?
                .into_iter()
                .map(|u| UserAndGroups {
                    user: u,
                    groups: None,
                })
                .collect())
        } else {
            let results = query
                //find_with_linked?
                .find_also_linked(model::memberships::UserToGroup)
                .order_by_asc(SimpleExpr::Column(
                    (Alias::new("r1"), GroupColumn::GroupId).into_column_ref(),
                ))
                .all(&self.sql_pool)
                .await?;
            use itertools::Itertools;
            Ok(results
                .iter()
                .group_by(|(u, _)| u)
                .into_iter()
                .map(|(user, groups)| {
                    let groups: Vec<_> = groups
                        .into_iter()
                        .flat_map(|(_, g)| g)
                        .map(|g| GroupDetails::from(g.clone()))
                        .collect();
                    UserAndGroups {
                        user: user.clone().into(),
                        groups: Some(groups),
                    }
                })
                .collect())
        }
    }

    #[instrument(skip_all, level = "debug", ret)]
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        debug!(?user_id);
        model::User::find_by_id(user_id.to_owned())
            .into_model::<User>()
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))
    }

    #[instrument(skip_all, level = "debug", ret, err)]
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        debug!(?user_id);
        let user = model::User::find_by_id(user_id.to_owned())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))?;
        Ok(HashSet::from_iter(
            user.find_linked(model::memberships::UserToGroup)
                .into_model::<GroupDetails>()
                .all(&self.sql_pool)
                .await?,
        ))
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        debug!(user_id = ?request.user_id);
        let now = chrono::Utc::now();
        let uuid = Uuid::from_name_and_date(request.user_id.as_str(), &now);
        let new_user = model::users::ActiveModel {
            user_id: Set(request.user_id),
            email: Set(request.email),
            display_name: to_value(&request.display_name),
            first_name: to_value(&request.first_name),
            last_name: to_value(&request.last_name),
            avatar: request.avatar.into_active_value(),
            creation_date: ActiveValue::Set(now),
            uuid: ActiveValue::Set(uuid),
            ..Default::default()
        };
        new_user.insert(&self.sql_pool).await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        debug!(user_id = ?request.user_id);
        let update_user = model::users::ActiveModel {
            email: request.email.map(ActiveValue::Set).unwrap_or_default(),
            display_name: to_value(&request.display_name),
            first_name: to_value(&request.first_name),
            last_name: to_value(&request.last_name),
            avatar: request.avatar.into_active_value(),
            ..Default::default()
        };
        model::User::update_many()
            .set(update_user)
            .filter(sea_orm::ColumnTrait::eq(
                &UserColumn::UserId,
                request.user_id,
            ))
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        debug!(?user_id);
        let res = model::User::delete_by_id(user_id.clone())
            .exec(&self.sql_pool)
            .await?;
        if res.rows_affected == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such user: '{}'",
                user_id
            )));
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        debug!(?user_id, ?group_id);
        let new_membership = model::memberships::ActiveModel {
            user_id: ActiveValue::Set(user_id.clone()),
            group_id: ActiveValue::Set(group_id),
        };
        new_membership.insert(&self.sql_pool).await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        debug!(?user_id, ?group_id);
        let res = model::Membership::delete_by_id((user_id.clone(), group_id))
            .exec(&self.sql_pool)
            .await?;
        if res.rows_affected == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such membership: '{}' -> {:?}",
                user_id, group_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        handler::{JpegPhoto, UserColumn},
        sql_backend_handler::tests::*,
    };

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
                UserColumn::DisplayName,
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
                UserColumn::FirstName,
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
    async fn test_list_users_member_of_and_uuid() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::MemberOf("Best Group".to_string()),
                UserRequestFilter::Equality(UserColumn::Uuid, "abc".to_string()),
            ])),
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
                UserColumn::UserId,
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
                    u.user
                        .display_name
                        .as_deref()
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    u.groups
                        .unwrap_or_default()
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
                        .unwrap_or_default()
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
                avatar: Some(JpegPhoto::for_tests()),
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(user.email, "email");
        assert_eq!(user.display_name.unwrap(), "display_name");
        assert_eq!(user.first_name.unwrap(), "first_name");
        assert_eq!(user.last_name.unwrap(), "last_name");
        assert_eq!(user.avatar, Some(JpegPhoto::for_tests()));
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
        assert_eq!(user.display_name.unwrap(), "display bob");
        assert_eq!(user.first_name.unwrap(), "first_name");
        assert_eq!(user.last_name, None);
        assert_eq!(user.avatar, None);
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
