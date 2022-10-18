use super::{
    error::Result,
    handler::{
        Group, GroupBackendHandler, GroupDetails, GroupId, GroupRequestFilter, UpdateGroupRequest,
        UserId,
    },
    sql_backend_handler::SqlBackendHandler,
    sql_tables::{DbQueryBuilder, Groups, Memberships},
};
use async_trait::async_trait;
use sea_query::{Cond, Expr, Iden, Order, Query, SimpleExpr};
use sea_query_binder::SqlxBinder;
use sqlx::{query_as_with, query_with, FromRow, Row};
use tracing::{debug, instrument};

// Returns the condition for the SQL query, and whether it requires joining with the groups table.
fn get_group_filter_expr(filter: GroupRequestFilter) -> Cond {
    use sea_query::IntoCondition;
    use GroupRequestFilter::*;
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
impl GroupBackendHandler for SqlBackendHandler {
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
                query_builder.cond_where(get_group_filter_expr(filter));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::sql_backend_handler::tests::*;

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

    #[tokio::test]
    async fn test_list_groups_no_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(&fixture.handler, None).await,
            vec![fixture.groups[0], fixture.groups[2], fixture.groups[1]]
        );
    }

    #[tokio::test]
    async fn test_list_groups_simple_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::Or(vec![
                    GroupRequestFilter::DisplayName("Empty Group".to_string()),
                    GroupRequestFilter::Member(UserId::new("bob")),
                ]))
            )
            .await,
            vec![fixture.groups[0], fixture.groups[2]]
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
                        "value".to_string()
                    ))),
                    GroupRequestFilter::GroupId(fixture.groups[0]),
                ]))
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
                display_name: Some("Awesomest Group".to_string()),
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
