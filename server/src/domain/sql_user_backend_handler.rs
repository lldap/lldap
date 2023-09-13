use crate::domain::{
    error::{DomainError, Result},
    handler::{
        CreateUserRequest, UpdateUserRequest, UserBackendHandler, UserListerBackendHandler,
        UserRequestFilter,
    },
    model::{self, GroupColumn, UserColumn},
    sql_backend_handler::SqlBackendHandler,
    types::{AttributeValue, GroupDetails, GroupId, Serialized, User, UserAndGroups, UserId, Uuid},
};
use async_trait::async_trait;
use sea_orm::{
    sea_query::{
        query::OnConflict, Alias, Cond, Expr, Func, IntoColumnRef, IntoCondition, SimpleExpr,
    },
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, IntoActiveValue, ModelTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set, TransactionTrait,
};
use std::collections::HashSet;
use tracing::instrument;

fn attribute_condition(name: String, value: String) -> Cond {
    Expr::in_subquery(
        Expr::col(UserColumn::UserId.as_column_ref()),
        model::UserAttributes::find()
            .select_only()
            .column(model::UserAttributesColumn::UserId)
            .filter(model::UserAttributesColumn::AttributeName.eq(name))
            .filter(model::UserAttributesColumn::Value.eq(Serialized::from(&value)))
            .into_query(),
    )
    .into_condition()
}

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
        AttributeEquality(s1, s2) => attribute_condition(s1, s2),
        MemberOf(group) => Expr::col((group_table, GroupColumn::DisplayName))
            .eq(group)
            .into_condition(),
        MemberOfId(group_id) => Expr::col((group_table, GroupColumn::GroupId))
            .eq(group_id)
            .into_condition(),
        UserIdSubString(filter) => UserColumn::UserId
            .like(filter.to_sql_filter())
            .into_condition(),
        SubString(col, filter) => {
            SimpleExpr::FunctionCall(Func::lower(Expr::col(col.as_column_ref())))
                .like(filter.to_sql_filter())
                .into_condition()
        }
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
impl UserListerBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        // To simplify the query, we always fetch groups. TODO: cleanup.
        _get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        let mut users: Vec<_> = model::User::find()
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
            .order_by_asc(UserColumn::UserId)
            .find_with_linked(model::memberships::UserToGroup)
            .order_by_asc(SimpleExpr::Column(
                (Alias::new("r1"), GroupColumn::DisplayName).into_column_ref(),
            ))
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|(user, groups)| UserAndGroups {
                user: user.into(),
                groups: Some(groups.into_iter().map(Into::<GroupDetails>::into).collect()),
            })
            .collect();
        // At this point, the users don't have attributes, we need to populate it with another query.
        let user_ids = users.iter().map(|u| &u.user.user_id);
        let attributes = model::UserAttributes::find()
            .filter(model::UserAttributesColumn::UserId.is_in(user_ids))
            .order_by_asc(model::UserAttributesColumn::UserId)
            .order_by_asc(model::UserAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        let mut attributes_iter = attributes.into_iter().peekable();
        use itertools::Itertools; // For take_while_ref
        for user in users.iter_mut() {
            assert!(attributes_iter
                .peek()
                .map(|u| u.user_id >= user.user.user_id)
                .unwrap_or(true),
                "Attributes are not sorted, users are not sorted, or previous user didn't consume all the attributes");

            user.user.attributes = attributes_iter
                .take_while_ref(|u| u.user_id == user.user.user_id)
                .map(AttributeValue::from)
                .collect();
        }
        Ok(users)
    }
}

#[async_trait]
impl UserBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", ret, fields(user_id = ?user_id.as_str()))]
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        let mut user = User::from(
            model::User::find_by_id(user_id.to_owned())
                .one(&self.sql_pool)
                .await?
                .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))?,
        );
        let attributes = model::UserAttributes::find()
            .filter(model::UserAttributesColumn::UserId.eq(user_id))
            .order_by_asc(model::UserAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        user.attributes = attributes.into_iter().map(AttributeValue::from).collect();
        Ok(user)
    }

    #[instrument(skip_all, level = "debug", ret, err, fields(user_id = ?user_id.as_str()))]
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        let user = model::User::find_by_id(user_id.to_owned())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))?;
        Ok(HashSet::from_iter(
            user.find_linked(model::memberships::UserToGroup)
                .all(&self.sql_pool)
                .await?
                .into_iter()
                .map(Into::<GroupDetails>::into),
        ))
    }

    #[instrument(skip(self), level = "debug", err, fields(user_id = ?request.user_id.as_str()))]
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        let now = chrono::Utc::now().naive_utc();
        let uuid = Uuid::from_name_and_date(request.user_id.as_str(), &now);
        let new_user = model::users::ActiveModel {
            user_id: Set(request.user_id.clone()),
            email: Set(request.email),
            display_name: to_value(&request.display_name),
            creation_date: ActiveValue::Set(now),
            uuid: ActiveValue::Set(uuid),
            ..Default::default()
        };
        let mut new_user_attributes = Vec::new();
        if let Some(first_name) = request.first_name {
            new_user_attributes.push(model::user_attributes::ActiveModel {
                user_id: Set(request.user_id.clone()),
                attribute_name: Set("first_name".to_owned()),
                value: Set(Serialized::from(&first_name)),
            });
        }
        if let Some(last_name) = request.last_name {
            new_user_attributes.push(model::user_attributes::ActiveModel {
                user_id: Set(request.user_id.clone()),
                attribute_name: Set("last_name".to_owned()),
                value: Set(Serialized::from(&last_name)),
            });
        }
        if let Some(avatar) = request.avatar {
            new_user_attributes.push(model::user_attributes::ActiveModel {
                user_id: Set(request.user_id),
                attribute_name: Set("avatar".to_owned()),
                value: Set(Serialized::from(&avatar)),
            });
        }
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    new_user.insert(transaction).await?;
                    if !new_user_attributes.is_empty() {
                        model::UserAttributes::insert_many(new_user_attributes)
                            .exec(transaction)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip(self), level = "debug", err, fields(user_id = ?request.user_id.as_str()))]
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        let update_user = model::users::ActiveModel {
            user_id: ActiveValue::Set(request.user_id.clone()),
            email: request.email.map(ActiveValue::Set).unwrap_or_default(),
            display_name: to_value(&request.display_name),
            ..Default::default()
        };
        let mut update_user_attributes = Vec::new();
        let mut remove_user_attributes = Vec::new();
        let to_serialized_value = |s: &Option<String>| match s.as_ref().map(|s| s.as_str()) {
            None => None,
            Some("") => Some(ActiveValue::NotSet),
            Some(s) => Some(ActiveValue::Set(Serialized::from(s))),
        };
        let mut process_serialized =
            |value: ActiveValue<Serialized>, attribute_name: &str| match &value {
                ActiveValue::NotSet => {
                    remove_user_attributes.push(attribute_name.to_owned());
                }
                ActiveValue::Set(_) => {
                    update_user_attributes.push(model::user_attributes::ActiveModel {
                        user_id: Set(request.user_id.clone()),
                        attribute_name: Set(attribute_name.to_owned()),
                        value,
                    })
                }
                _ => unreachable!(),
            };
        if let Some(value) = to_serialized_value(&request.first_name) {
            process_serialized(value, "first_name");
        }
        if let Some(value) = to_serialized_value(&request.last_name) {
            process_serialized(value, "last_name");
        }
        if let Some(avatar) = request.avatar {
            process_serialized(avatar.into_active_value(), "avatar");
        }
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    update_user.update(transaction).await?;
                    if !update_user_attributes.is_empty() {
                        model::UserAttributes::insert_many(update_user_attributes)
                            .on_conflict(
                                OnConflict::columns([
                                    model::UserAttributesColumn::UserId,
                                    model::UserAttributesColumn::AttributeName,
                                ])
                                .update_column(model::UserAttributesColumn::Value)
                                .to_owned(),
                            )
                            .exec(transaction)
                            .await?;
                    }
                    if !remove_user_attributes.is_empty() {
                        model::UserAttributes::delete_many()
                            .filter(model::UserAttributesColumn::UserId.eq(&request.user_id))
                            .filter(
                                model::UserAttributesColumn::AttributeName
                                    .is_in(remove_user_attributes),
                            )
                            .exec(transaction)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
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

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        let new_membership = model::memberships::ActiveModel {
            user_id: ActiveValue::Set(user_id.clone()),
            group_id: ActiveValue::Set(group_id),
        };
        new_membership.insert(&self.sql_pool).await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
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
        handler::SubStringFilter,
        sql_backend_handler::tests::*,
        types::{JpegPhoto, UserColumn},
    };
    use pretty_assertions::{assert_eq, assert_ne};

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
            Some(UserRequestFilter::AttributeEquality(
                "first_name".to_string(),
                "first bob".to_string(),
            )),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_substring_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::And(vec![
                UserRequestFilter::UserIdSubString(SubStringFilter {
                    initial: Some("Pa".to_owned()),
                    any: vec!["rI".to_owned()],
                    final_: Some("K".to_owned()),
                }),
                UserRequestFilter::SubString(
                    UserColumn::DisplayName,
                    SubStringFilter {
                        initial: None,
                        any: vec!["t".to_owned(), "r".to_owned()],
                        final_: None,
                    },
                ),
            ])),
        )
        .await;
        assert_eq!(users, vec!["patrick"]);
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
        assert_eq!(
            user.attributes,
            vec![
                AttributeValue {
                    name: "avatar".to_owned(),
                    value: Serialized::from(&JpegPhoto::for_tests())
                },
                AttributeValue {
                    name: "first_name".to_owned(),
                    value: Serialized::from("first_name")
                },
                AttributeValue {
                    name: "last_name".to_owned(),
                    value: Serialized::from("last_name")
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_update_user_some_values() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                first_name: None,
                last_name: Some(String::new()),
                avatar: Some(JpegPhoto::for_tests()),
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
        assert_eq!(
            user.attributes,
            vec![
                AttributeValue {
                    name: "avatar".to_owned(),
                    value: Serialized::from(&JpegPhoto::for_tests())
                },
                AttributeValue {
                    name: "first_name".to_owned(),
                    value: Serialized::from("first bob")
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_update_user_delete_avatar() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                avatar: Some(JpegPhoto::for_tests()),
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        let avatar = AttributeValue {
            name: "avatar".to_owned(),
            value: Serialized::from(&JpegPhoto::for_tests()),
        };
        assert!(user.attributes.contains(&avatar));
        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                avatar: Some(JpegPhoto::null()),
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert!(!user.attributes.contains(&avatar));
    }

    #[tokio::test]
    async fn test_create_user_all_values() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("james"),
                email: "email".to_string(),
                display_name: Some("display_name".to_string()),
                first_name: Some("first_name".to_string()),
                last_name: Some("last_name".to_string()),
                avatar: Some(JpegPhoto::for_tests()),
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("james"))
            .await
            .unwrap();
        assert_eq!(user.email, "email");
        assert_eq!(user.display_name.unwrap(), "display_name");
        assert_eq!(
            user.attributes,
            vec![
                AttributeValue {
                    name: "avatar".to_owned(),
                    value: Serialized::from(&JpegPhoto::for_tests())
                },
                AttributeValue {
                    name: "first_name".to_owned(),
                    value: Serialized::from("first_name")
                },
                AttributeValue {
                    name: "last_name".to_owned(),
                    value: Serialized::from("last_name")
                }
            ]
        );
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

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .delete_user(&UserId::new("not found"))
            .await
            .expect_err("Should have failed");
    }

    #[tokio::test]
    async fn test_remove_user_from_group_not_found() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .remove_user_from_group(&UserId::new("not found"), fixture.groups[0])
            .await
            .expect_err("Should have failed");

        fixture
            .handler
            .remove_user_from_group(&UserId::new("not found"), GroupId(16242))
            .await
            .expect_err("Should have failed");
    }
}
