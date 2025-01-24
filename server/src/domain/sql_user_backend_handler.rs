use crate::domain::{
    error::{DomainError, Result},
    handler::{
        CreateUserRequest, UpdateUserRequest, UserBackendHandler, UserListerBackendHandler,
        UserRequestFilter,
    },
    model::{self, GroupColumn, UserColumn},
    sql_backend_handler::SqlBackendHandler,
};
use async_trait::async_trait;
use lldap_domain::types::{
    AttributeName, AttributeValue, GroupDetails, GroupId, Serialized, User, UserAndGroups, UserId,
    Uuid,
};
use sea_orm::{
    sea_query::{
        query::OnConflict, Alias, Cond, Expr, Func, IntoColumnRef, IntoCondition, SimpleExpr,
    },
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseTransaction, EntityTrait, IntoActiveValue,
    ModelTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set, TransactionTrait,
};
use std::collections::HashSet;
use tracing::instrument;

fn attribute_condition(name: AttributeName, value: Option<Serialized>) -> Cond {
    Expr::in_subquery(
        Expr::col(UserColumn::UserId.as_column_ref()),
        model::UserAttributes::find()
            .select_only()
            .column(model::UserAttributesColumn::UserId)
            .filter(model::UserAttributesColumn::AttributeName.eq(name))
            .filter(
                value
                    .map(|value| model::UserAttributesColumn::Value.eq(value))
                    .unwrap_or_else(|| SimpleExpr::Constant(true.into())),
            )
            .into_query(),
    )
    .into_condition()
}

fn user_id_subcondition(filter: Cond) -> Cond {
    Expr::in_subquery(
        Expr::col(UserColumn::UserId.as_column_ref()),
        model::User::find()
            .find_also_linked(model::memberships::UserToGroup)
            .select_only()
            .column(UserColumn::UserId)
            .filter(filter)
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
        Equality(column, value) => {
            if column == UserColumn::UserId {
                panic!("User id should be wrapped")
            } else if column == UserColumn::Email {
                ColumnTrait::eq(&UserColumn::LowercaseEmail, value.as_str().to_lowercase())
                    .into_condition()
            } else {
                ColumnTrait::eq(&column, value).into_condition()
            }
        }
        AttributeEquality(column, value) => attribute_condition(column, Some(value)),
        MemberOf(group) => user_id_subcondition(
            Expr::col((group_table, GroupColumn::LowercaseDisplayName))
                .eq(group.as_str().to_lowercase())
                .into_condition(),
        ),
        MemberOfId(group_id) => user_id_subcondition(
            Expr::col((group_table, GroupColumn::GroupId))
                .eq(group_id)
                .into_condition(),
        ),
        UserIdSubString(filter) => UserColumn::UserId
            .like(filter.to_sql_filter())
            .into_condition(),
        SubString(col, filter) => {
            SimpleExpr::FunctionCall(Func::lower(Expr::col(col.as_column_ref())))
                .like(filter.to_sql_filter())
                .into_condition()
        }
        CustomAttributePresent(name) => attribute_condition(name, None),
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
        let filters = filters
            .map(get_user_filter_expr)
            .unwrap_or_else(|| SimpleExpr::Value(true.into()).into_condition());
        let mut users: Vec<_> = model::User::find()
            .filter(filters.clone())
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
        let attributes = model::UserAttributes::find()
            .filter(
                model::UserAttributesColumn::UserId.in_subquery(
                    model::User::find()
                        .filter(filters)
                        .select_only()
                        .column(model::users::Column::UserId)
                        .into_query(),
                ),
            )
            .order_by_asc(model::UserAttributesColumn::UserId)
            .order_by_asc(model::UserAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        let mut attributes_iter = attributes.into_iter().peekable();
        use itertools::Itertools; // For take_while_ref
        for user in users.iter_mut() {
            user.user.attributes = attributes_iter
                .take_while_ref(|u| u.user_id == user.user.user_id)
                .map(AttributeValue::from)
                .collect();
        }
        Ok(users)
    }
}

impl SqlBackendHandler {
    async fn update_user_with_transaction(
        transaction: &DatabaseTransaction,
        request: UpdateUserRequest,
    ) -> Result<()> {
        let lower_email = request.email.as_ref().map(|s| s.as_str().to_lowercase());
        let update_user = model::users::ActiveModel {
            user_id: ActiveValue::Set(request.user_id.clone()),
            email: request.email.map(ActiveValue::Set).unwrap_or_default(),
            lowercase_email: lower_email.map(ActiveValue::Set).unwrap_or_default(),
            display_name: to_value(&request.display_name),
            ..Default::default()
        };
        let to_serialized_value = |s: &Option<String>| match s.as_ref().map(|s| s.as_str()) {
            None => None,
            Some("") => Some(ActiveValue::NotSet),
            Some(s) => Some(ActiveValue::Set(Serialized::from(s))),
        };
        let mut update_user_attributes = Vec::new();
        let mut remove_user_attributes = Vec::new();
        let mut process_serialized =
            |value: ActiveValue<Serialized>, attribute_name: AttributeName| match &value {
                ActiveValue::NotSet => {
                    remove_user_attributes.push(attribute_name);
                }
                ActiveValue::Set(_) => {
                    update_user_attributes.push(model::user_attributes::ActiveModel {
                        user_id: Set(request.user_id.clone()),
                        attribute_name: Set(attribute_name),
                        value,
                    })
                }
                _ => unreachable!(),
            };
        if let Some(value) = to_serialized_value(&request.first_name) {
            process_serialized(value, "first_name".into());
        }
        if let Some(value) = to_serialized_value(&request.last_name) {
            process_serialized(value, "last_name".into());
        }
        if let Some(avatar) = request.avatar {
            process_serialized(avatar.into_active_value(), "avatar".into());
        }
        let schema = Self::get_schema_with_transaction(transaction).await?;
        for attribute in request.insert_attributes {
            if schema
                .user_attributes
                .get_attribute_type(&attribute.name)
                .is_some()
            {
                process_serialized(ActiveValue::Set(attribute.value), attribute.name.clone());
            } else {
                return Err(DomainError::InternalError(format!(
                    "User attribute name {} doesn't exist in the schema, yet was attempted to be inserted in the database",
                    &attribute.name
                )));
            }
        }
        for attribute in request.delete_attributes {
            if schema
                .user_attributes
                .get_attribute_type(&attribute)
                .is_some()
            {
                remove_user_attributes.push(attribute);
            } else {
                return Err(DomainError::InternalError(format!(
                    "User attribute name {} doesn't exist in the schema, yet was attempted to be removed from the database",
                    attribute
                )));
            }
        }
        update_user.update(transaction).await?;
        if !remove_user_attributes.is_empty() {
            model::UserAttributes::delete_many()
                .filter(model::UserAttributesColumn::UserId.eq(&request.user_id))
                .filter(model::UserAttributesColumn::AttributeName.is_in(remove_user_attributes))
                .exec(transaction)
                .await?;
        }
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
        Ok(())
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
        let lower_email = request.email.as_str().to_lowercase();
        let new_user = model::users::ActiveModel {
            user_id: Set(request.user_id.clone()),
            email: Set(request.email),
            lowercase_email: Set(lower_email),
            display_name: to_value(&request.display_name),
            creation_date: ActiveValue::Set(now),
            uuid: ActiveValue::Set(uuid),
            ..Default::default()
        };
        let mut new_user_attributes = Vec::new();
        if let Some(first_name) = request.first_name {
            new_user_attributes.push(model::user_attributes::ActiveModel {
                user_id: Set(request.user_id.clone()),
                attribute_name: Set("first_name".into()),
                value: Set(Serialized::from(&first_name)),
            });
        }
        if let Some(last_name) = request.last_name {
            new_user_attributes.push(model::user_attributes::ActiveModel {
                user_id: Set(request.user_id.clone()),
                attribute_name: Set("last_name".into()),
                value: Set(Serialized::from(&last_name)),
            });
        }
        if let Some(avatar) = request.avatar {
            new_user_attributes.push(model::user_attributes::ActiveModel {
                user_id: Set(request.user_id.clone()),
                attribute_name: Set("avatar".into()),
                value: Set(Serialized::from(&avatar)),
            });
        }
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    let schema = Self::get_schema_with_transaction(transaction).await?;
                    for attribute in request.attributes {
                        if schema
                            .user_attributes
                            .get_attribute_type(&attribute.name)
                            .is_some()
                        {
                            new_user_attributes.push(model::user_attributes::ActiveModel {
                                user_id: Set(request.user_id.clone()),
                                attribute_name: Set(attribute.name),
                                value: Set(attribute.value),
                            });
                        } else {
                            return Err(DomainError::InternalError(format!(
                                "Attribute name {} doesn't exist in the user schema,
                                    yet was attempted to be inserted in the database",
                                &attribute.name
                            )));
                        }
                    }
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
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(
                    async move { Self::update_user_with_transaction(transaction, request).await },
                )
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
        handler::SubStringFilter, model::UserColumn, sql_backend_handler::tests::*,
    };
    use lldap_domain::types::JpegPhoto;
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
                AttributeName::from("first_name"),
                Serialized::from("first bob"),
            )),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_email_filter_uppercase_email() {
        let fixture = TestFixture::new().await;
        insert_user_no_password(&fixture.handler, "UppEr").await;
        let users_and_emails = fixture
            .handler
            .list_users(
                Some(UserRequestFilter::Equality(
                    UserColumn::Email,
                    "uPPer@bob.bob".to_string(),
                )),
                false,
            )
            .await
            .unwrap()
            .into_iter()
            .map(|u| (u.user.user_id.to_string(), u.user.email.to_string()))
            .collect::<Vec<_>>();
        assert_eq!(
            users_and_emails,
            vec![("upper".to_owned(), "UppEr@bob.bob".to_owned())]
        );
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
            Some(UserRequestFilter::MemberOf("Best Group".into())),
        )
        .await;
        assert_eq!(users, vec!["bob", "patrick"]);
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::MemberOf("best grOUp".into())),
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
                UserRequestFilter::MemberOf("Best Group".into()),
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
    async fn test_list_users_filter_several_member_of() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::And(vec![
                UserRequestFilter::MemberOf("Best Group".into()),
                UserRequestFilter::MemberOf("Worst Group".into()),
            ])),
        )
        .await;
        assert_eq!(users, vec!["patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_filter_several_member_of_id() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::And(vec![
                UserRequestFilter::MemberOfId(fixture.groups[0]),
                UserRequestFilter::MemberOfId(fixture.groups[1]),
            ])),
        )
        .await;
        assert_eq!(users, vec!["patrick"]);
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
                email: Some("email".into()),
                display_name: Some("display_name".to_string()),
                first_name: Some("first_name".to_string()),
                last_name: Some("last_name".to_string()),
                avatar: Some(JpegPhoto::for_tests()),
                delete_attributes: Vec::new(),
                insert_attributes: Vec::new(),
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(user.email, "email".into());
        assert_eq!(user.display_name.unwrap(), "display_name");
        assert_eq!(
            user.attributes,
            vec![
                AttributeValue {
                    name: "avatar".into(),
                    value: Serialized::from(&JpegPhoto::for_tests())
                },
                AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("first_name")
                },
                AttributeValue {
                    name: "last_name".into(),
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
                    name: "avatar".into(),
                    value: Serialized::from(&JpegPhoto::for_tests())
                },
                AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("first bob")
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_update_user_insert_attribute() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                first_name: None,
                last_name: None,
                avatar: None,
                insert_attributes: vec![AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("new first"),
                }],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(
            user.attributes,
            vec![
                AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("new first")
                },
                AttributeValue {
                    name: "last_name".into(),
                    value: Serialized::from("last bob")
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_update_user_delete_attribute() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                first_name: None,
                last_name: None,
                avatar: None,
                delete_attributes: vec!["first_name".into()],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(
            user.attributes,
            vec![AttributeValue {
                name: "last_name".into(),
                value: Serialized::from("last bob")
            }]
        );
    }

    #[tokio::test]
    async fn test_update_user_replace_attribute() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                first_name: None,
                last_name: None,
                avatar: None,
                delete_attributes: vec!["first_name".into()],
                insert_attributes: vec![AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("new first"),
                }],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(
            user.attributes,
            vec![
                AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("new first")
                },
                AttributeValue {
                    name: "last_name".into(),
                    value: Serialized::from("last bob")
                },
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
            name: "avatar".into(),
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
                email: "email".into(),
                display_name: Some("display_name".to_string()),
                first_name: None,
                last_name: Some("last_name".to_string()),
                avatar: Some(JpegPhoto::for_tests()),
                attributes: vec![AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("First Name"),
                }],
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("james"))
            .await
            .unwrap();
        assert_eq!(user.email, "email".into());
        assert_eq!(user.display_name.unwrap(), "display_name");
        assert_eq!(
            user.attributes,
            vec![
                AttributeValue {
                    name: "avatar".into(),
                    value: Serialized::from(&JpegPhoto::for_tests())
                },
                AttributeValue {
                    name: "first_name".into(),
                    value: Serialized::from("First Name")
                },
                AttributeValue {
                    name: "last_name".into(),
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

    #[tokio::test]
    async fn test_create_user_duplicate_email() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("james"),
                email: "email".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("john"),
                email: "eMail".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
    }
}
