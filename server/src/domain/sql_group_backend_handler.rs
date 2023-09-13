use crate::domain::{
    error::{DomainError, Result},
    handler::{
        GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter, UpdateGroupRequest,
    },
    model::{self, GroupColumn, MembershipColumn},
    sql_backend_handler::SqlBackendHandler,
    types::{AttributeValue, Group, GroupDetails, GroupId, Uuid},
};
use async_trait::async_trait;
use sea_orm::{
    sea_query::{Alias, Cond, Expr, Func, IntoCondition, SimpleExpr},
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    QueryTrait,
};
use tracing::instrument;

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
        DisplayName(name) => GroupColumn::DisplayName.eq(name).into_condition(),
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
            GroupColumn::DisplayName,
        ))))
        .like(filter.to_sql_filter())
        .into_condition(),
    }
}

#[async_trait]
impl GroupListerBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        let results = model::Group::find()
            .order_by_asc(GroupColumn::GroupId)
            .find_with_related(model::Membership)
            .filter(
                filters
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
                    .unwrap_or_else(|| SimpleExpr::Value(true.into()).into_condition()),
            )
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
        let group_ids = groups.iter().map(|u| &u.id);
        let attributes = model::GroupAttributes::find()
            .filter(model::GroupAttributesColumn::GroupId.is_in(group_ids))
            .order_by_asc(model::GroupAttributesColumn::GroupId)
            .order_by_asc(model::GroupAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        let mut attributes_iter = attributes.into_iter().peekable();
        use itertools::Itertools; // For take_while_ref
        for group in groups.iter_mut() {
            assert!(attributes_iter
                .peek()
                .map(|u| u.group_id >= group.id)
                .unwrap_or(true),
                "Attributes are not sorted, groups are not sorted, or previous group didn't consume all the attributes");

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
        let update_group = model::groups::ActiveModel {
            group_id: ActiveValue::Set(request.group_id),
            display_name: request
                .display_name
                .map(ActiveValue::Set)
                .unwrap_or_default(),
            ..Default::default()
        };
        update_group.update(&self.sql_pool).await?;
        Ok(())
    }

    #[instrument(skip(self), level = "debug", ret, err)]
    async fn create_group(&self, group_name: &str) -> Result<GroupId> {
        let now = chrono::Utc::now().naive_utc();
        let uuid = Uuid::from_name_and_date(group_name, &now);
        let new_group = model::groups::ActiveModel {
            display_name: ActiveValue::Set(group_name.to_owned()),
            creation_date: ActiveValue::Set(now),
            uuid: ActiveValue::Set(uuid),
            ..Default::default()
        };
        Ok(new_group.insert(&self.sql_pool).await?.group_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{handler::SubStringFilter, sql_backend_handler::tests::*, types::UserId};
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
    ) -> Vec<String> {
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
                "Best Group".to_owned(),
                "Empty Group".to_owned(),
                "Worst Group".to_owned()
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
                    GroupRequestFilter::DisplayName("Empty Group".to_owned()),
                    GroupRequestFilter::Member(UserId::new("bob")),
                ]))
            )
            .await,
            vec!["Best Group".to_owned(), "Empty Group".to_owned()]
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
                        "value".to_owned()
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
    async fn test_get_group_details() {
        let fixture = TestFixture::new().await;
        let details = fixture
            .handler
            .get_group_details(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(details.group_id, fixture.groups[0]);
        assert_eq!(details.display_name, "Best Group");
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
                display_name: Some("Awesomest Group".to_owned()),
            })
            .await
            .unwrap();
        let details = fixture
            .handler
            .get_group_details(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(details.display_name, "Awesomest Group");
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
}
