use crate::domain::{
    error::{DomainError, Result},
    handler::{
        CreateGroupRequest, GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter,
        UpdateGroupRequest,
    },
    model::{self, GroupColumn, MembershipColumn},
    sql_backend_handler::SqlBackendHandler,
    types::{AttributeName, AttributeValue, Group, GroupDetails, GroupId, Serialized, Uuid},
};
use async_trait::async_trait;
use sea_orm::{
    sea_query::{Alias, Cond, Expr, Func, IntoCondition, OnConflict, SimpleExpr},
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, Set, TransactionTrait,
};
use tracing::instrument;

fn attribute_condition(name: AttributeName, value: Option<Serialized>) -> Cond {
    Expr::in_subquery(
        Expr::col(GroupColumn::GroupId.as_column_ref()),
        model::GroupAttributes::find()
            .select_only()
            .column(model::GroupAttributesColumn::GroupId)
            .filter(model::GroupAttributesColumn::AttributeName.eq(name))
            .filter(
                value
                    .map(|value| model::GroupAttributesColumn::Value.eq(value))
                    .unwrap_or_else(|| SimpleExpr::Value(true.into())),
            )
            .into_query(),
    )
    .into_condition()
}

fn get_group_filter_expr(filter: GroupRequestFilter) -> Cond {
    use GroupRequestFilter::*;
    let group_table = Alias::new("groups");
    match filter {
        And(fs) => {
            if fs.is_empty() {
                SimpleExpr::Value(true.into()).into_condition()
            } else {
                fs.into_iter()
                    .fold(Cond::all(), |c, f| c.add(get_group_filter_expr(f)))
            }
        }
        Or(fs) => {
            if fs.is_empty() {
                SimpleExpr::Value(false.into()).into_condition()
            } else {
                fs.into_iter()
                    .fold(Cond::any(), |c, f| c.add(get_group_filter_expr(f)))
            }
        }
        Not(f) => get_group_filter_expr(*f).not(),
        DisplayName(name) => GroupColumn::LowercaseDisplayName
            .eq(name.as_str().to_lowercase())
            .into_condition(),
        GroupId(id) => GroupColumn::GroupId.eq(id.0).into_condition(),
        Uuid(uuid) => GroupColumn::Uuid.eq(uuid.to_string()).into_condition(),
        // WHERE (group_id in (SELECT group_id FROM memberships WHERE user_id = user))
        Member(user) => GroupColumn::GroupId
            .in_subquery(
                model::Membership::find()
                    .select_only()
                    .column(MembershipColumn::GroupId)
                    .filter(MembershipColumn::UserId.eq(user))
                    .into_query(),
            )
            .into_condition(),
        DisplayNameSubString(filter) => SimpleExpr::FunctionCall(Func::lower(Expr::col((
            group_table,
            GroupColumn::LowercaseDisplayName,
        ))))
        .like(filter.to_sql_filter())
        .into_condition(),
        AttributeEquality(name, value) => attribute_condition(name, Some(value)),
        CustomAttributePresent(name) => attribute_condition(name, None),
    }
}

#[async_trait]
impl GroupListerBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        let filters = filters
            .map(|f| {
                GroupColumn::GroupId
                    .in_subquery(
                        model::Group::find()
                            .find_also_linked(model::memberships::GroupToUser)
                            .select_only()
                            .column(GroupColumn::GroupId)
                            .filter(get_group_filter_expr(f))
                            .into_query(),
                    )
                    .into_condition()
            })
            .unwrap_or_else(|| SimpleExpr::Value(true.into()).into_condition());
        let results = model::Group::find()
            .order_by_asc(GroupColumn::GroupId)
            .find_with_related(model::Membership)
            .filter(filters.clone())
            .all(&self.sql_pool)
            .await?;
        let mut groups: Vec<_> = results
            .into_iter()
            .map(|(group, users)| {
                let users: Vec<_> = users.into_iter().map(|u| u.user_id).collect();
                Group {
                    users,
                    ..group.into()
                }
            })
            .collect();
        let attributes = model::GroupAttributes::find()
            .filter(
                model::GroupAttributesColumn::GroupId.in_subquery(
                    model::Group::find()
                        .filter(filters)
                        .select_only()
                        .column(model::groups::Column::GroupId)
                        .into_query(),
                ),
            )
            .order_by_asc(model::GroupAttributesColumn::GroupId)
            .order_by_asc(model::GroupAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        let mut attributes_iter = attributes.into_iter().peekable();
        use itertools::Itertools; // For take_while_ref
        for group in groups.iter_mut() {
            group.attributes = attributes_iter
                .take_while_ref(|u| u.group_id == group.id)
                .map(AttributeValue::from)
                .collect();
        }
        groups.sort_by(|g1, g2| g1.display_name.cmp(&g2.display_name));
        Ok(groups)
    }
}

#[async_trait]
impl GroupBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails> {
        let mut group_details = model::Group::find_by_id(group_id)
            .one(&self.sql_pool)
            .await?
            .map(Into::<GroupDetails>::into)
            .ok_or_else(|| DomainError::EntityNotFound(format!("{:?}", group_id)))?;
        let attributes = model::GroupAttributes::find()
            .filter(model::GroupAttributesColumn::GroupId.eq(group_details.group_id))
            .order_by_asc(model::GroupAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        group_details.attributes = attributes.into_iter().map(AttributeValue::from).collect();
        Ok(group_details)
    }

    #[instrument(skip(self), level = "debug", err, fields(group_id = ?request.group_id))]
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        Ok(self
            .sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(
                    async move { Self::update_group_with_transaction(request, transaction).await },
                )
            })
            .await?)
    }

    #[instrument(skip(self), level = "debug", ret, err)]
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId> {
        let now = chrono::Utc::now().naive_utc();
        let uuid = Uuid::from_name_and_date(request.display_name.as_str(), &now);
        let lower_display_name = request.display_name.as_str().to_lowercase();
        let new_group = model::groups::ActiveModel {
            display_name: Set(request.display_name),
            lowercase_display_name: Set(lower_display_name),
            creation_date: Set(now),
            uuid: Set(uuid),
            ..Default::default()
        };
        Ok(self
            .sql_pool
            .transaction::<_, GroupId, DomainError>(|transaction| {
                Box::pin(async move {
                    let schema = Self::get_schema_with_transaction(transaction).await?;
                    let group_id = new_group.insert(transaction).await?.group_id;
                    let mut new_group_attributes = Vec::new();
                    for attribute in request.attributes {
                        if schema
                            .group_attributes
                            .get_attribute_type(&attribute.name)
                            .is_some()
                        {
                            new_group_attributes.push(model::group_attributes::ActiveModel {
                                group_id: Set(group_id),
                                attribute_name: Set(attribute.name),
                                value: Set(attribute.value),
                            });
                        } else {
                            return Err(DomainError::InternalError(format!(
                                "Attribute name {} doesn't exist in the group schema,
                                    yet was attempted to be inserted in the database",
                                &attribute.name
                            )));
                        }
                    }
                    if !new_group_attributes.is_empty() {
                        model::GroupAttributes::insert_many(new_group_attributes)
                            .exec(transaction)
                            .await?;
                    }
                    Ok(group_id)
                })
            })
            .await?)
    }

    #[instrument(skip(self), level = "debug", err)]
    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        let res = model::Group::delete_by_id(group_id)
            .exec(&self.sql_pool)
            .await?;
        if res.rows_affected == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such group: '{:?}'",
                group_id
            )));
        }
        Ok(())
    }
}

impl SqlBackendHandler {
    async fn update_group_with_transaction(
        request: UpdateGroupRequest,
        transaction: &DatabaseTransaction,
    ) -> Result<()> {
        let lower_display_name = request
            .display_name
            .as_ref()
            .map(|s| s.as_str().to_lowercase());
        let update_group = model::groups::ActiveModel {
            group_id: Set(request.group_id),
            display_name: request.display_name.map(Set).unwrap_or_default(),
            lowercase_display_name: lower_display_name.map(Set).unwrap_or_default(),
            ..Default::default()
        };
        update_group.update(transaction).await?;
        let mut update_group_attributes = Vec::new();
        let mut remove_group_attributes = Vec::new();
        let schema = Self::get_schema_with_transaction(transaction).await?;
        for attribute in request.insert_attributes {
            if schema
                .group_attributes
                .get_attribute_type(&attribute.name)
                .is_some()
            {
                update_group_attributes.push(model::group_attributes::ActiveModel {
                    group_id: Set(request.group_id),
                    attribute_name: Set(attribute.name.to_owned()),
                    value: Set(attribute.value),
                });
            } else {
                return Err(DomainError::InternalError(format!(
                    "Group attribute name {} doesn't exist in the schema, yet was attempted to be inserted in the database",
                    &attribute.name
                )));
            }
        }
        for attribute in request.delete_attributes {
            if schema
                .group_attributes
                .get_attribute_type(&attribute)
                .is_some()
            {
                remove_group_attributes.push(attribute);
            } else {
                return Err(DomainError::InternalError(format!(
                    "Group attribute name {} doesn't exist in the schema, yet was attempted to be removed from the database",
                    attribute
                )));
            }
        }
        if !remove_group_attributes.is_empty() {
            model::GroupAttributes::delete_many()
                .filter(model::GroupAttributesColumn::GroupId.eq(request.group_id))
                .filter(model::GroupAttributesColumn::AttributeName.is_in(remove_group_attributes))
                .exec(transaction)
                .await?;
        }
        if !update_group_attributes.is_empty() {
            model::GroupAttributes::insert_many(update_group_attributes)
                .on_conflict(
                    OnConflict::columns([
                        model::GroupAttributesColumn::GroupId,
                        model::GroupAttributesColumn::AttributeName,
                    ])
                    .update_column(model::GroupAttributesColumn::Value)
                    .to_owned(),
                )
                .exec(transaction)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        handler::{CreateAttributeRequest, SchemaBackendHandler, SubStringFilter},
        sql_backend_handler::tests::*,
        types::{AttributeType, GroupName, Serialized, UserId},
    };
    use pretty_assertions::assert_eq;

    async fn get_group_ids(
        handler: &SqlBackendHandler,
        filters: Option<GroupRequestFilter>,
    ) -> Vec<GroupId> {
        handler
            .list_groups(filters)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect::<Vec<_>>()
    }

    async fn get_group_names(
        handler: &SqlBackendHandler,
        filters: Option<GroupRequestFilter>,
    ) -> Vec<GroupName> {
        handler
            .list_groups(filters)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.display_name)
            .collect::<Vec<_>>()
    }

    #[tokio::test]
    async fn test_list_groups_no_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_names(&fixture.handler, None).await,
            vec![
                "Best Group".into(),
                "Empty Group".into(),
                "Worst Group".into()
            ]
        );
    }

    #[tokio::test]
    async fn test_list_groups_simple_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_names(
                &fixture.handler,
                Some(GroupRequestFilter::Or(vec![
                    GroupRequestFilter::DisplayName("Empty Group".into()),
                    GroupRequestFilter::Member(UserId::new("bob")),
                ]))
            )
            .await,
            vec!["Best Group".into(), "Empty Group".into()]
        );
    }

    #[tokio::test]
    async fn test_list_groups_case_insensitive_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_names(
                &fixture.handler,
                Some(GroupRequestFilter::DisplayName("eMpTy gRoup".into()),)
            )
            .await,
            vec!["Empty Group".into()]
        );
    }

    #[tokio::test]
    async fn test_list_groups_negation() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::And(vec![
                    GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                        "value".into()
                    ))),
                    GroupRequestFilter::GroupId(fixture.groups[0]),
                ]))
            )
            .await,
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_list_groups_substring_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::DisplayNameSubString(SubStringFilter {
                    initial: Some("be".to_owned()),
                    any: vec!["sT".to_owned()],
                    final_: Some("P".to_owned()),
                })),
            )
            .await,
            // Best group
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_list_groups_other_filter() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .add_group_attribute(CreateAttributeRequest {
                name: "gid".into(),
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: true,
            })
            .await
            .unwrap();
        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id: fixture.groups[0],
                display_name: None,
                delete_attributes: Vec::new(),
                insert_attributes: vec![AttributeValue {
                    name: "gid".into(),
                    value: Serialized::from(&512),
                }],
            })
            .await
            .unwrap();
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::AttributeEquality(
                    AttributeName::from("gid"),
                    Serialized::from(&512),
                )),
            )
            .await,
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_get_group_details() {
        let fixture = TestFixture::new().await;
        let details = fixture
            .handler
            .get_group_details(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(details.group_id, fixture.groups[0]);
        assert_eq!(details.display_name, "Best Group".into());
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::Uuid(details.uuid))
            )
            .await,
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_update_group() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id: fixture.groups[0],
                display_name: Some("Awesomest Group".into()),
                delete_attributes: Vec::new(),
                insert_attributes: Vec::new(),
            })
            .await
            .unwrap();
        let details = fixture
            .handler
            .get_group_details(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(details.display_name, "Awesomest Group".into());
    }

    #[tokio::test]
    async fn test_delete_group() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(&fixture.handler, None).await,
            vec![fixture.groups[0], fixture.groups[2], fixture.groups[1]]
        );
        fixture
            .handler
            .delete_group(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(
            get_group_ids(&fixture.handler, None).await,
            vec![fixture.groups[2], fixture.groups[1]]
        );
    }

    #[tokio::test]
    async fn test_create_group() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(&fixture.handler, None).await,
            vec![fixture.groups[0], fixture.groups[2], fixture.groups[1]]
        );
        fixture
            .handler
            .add_group_attribute(CreateAttributeRequest {
                name: "new_attribute".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
            })
            .await
            .unwrap();
        let new_group_id = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "New Group".into(),
                attributes: vec![AttributeValue {
                    name: "new_attribute".into(),
                    value: Serialized::from("value"),
                }],
            })
            .await
            .unwrap();
        let group_details = fixture
            .handler
            .get_group_details(new_group_id)
            .await
            .unwrap();
        assert_eq!(group_details.display_name, "New Group".into());
        assert_eq!(
            group_details.attributes,
            vec![AttributeValue {
                name: "new_attribute".into(),
                value: Serialized::from("value"),
            }]
        );
    }

    #[tokio::test]
    async fn test_set_group_attributes() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .add_group_attribute(CreateAttributeRequest {
                name: "new_attribute".into(),
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: true,
            })
            .await
            .unwrap();
        let group_id = fixture.groups[0];
        let attributes = vec![AttributeValue {
            name: "new_attribute".into(),
            value: Serialized::from(&42i64),
        }];
        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id,
                display_name: None,
                delete_attributes: Vec::new(),
                insert_attributes: attributes.clone(),
            })
            .await
            .unwrap();
        let details = fixture.handler.get_group_details(group_id).await.unwrap();
        assert_eq!(details.attributes, attributes);
        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id,
                display_name: None,
                delete_attributes: vec!["new_attribute".into()],
                insert_attributes: Vec::new(),
            })
            .await
            .unwrap();
        let details = fixture.handler.get_group_details(group_id).await.unwrap();
        assert_eq!(details.attributes, Vec::new());
    }

    #[tokio::test]
    async fn test_create_group_duplicate_name() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "New Group".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "neW group".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
    }
}
