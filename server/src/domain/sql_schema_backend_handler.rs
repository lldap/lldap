use crate::domain::{
    error::{DomainError, Result},
    handler::{AttributeList, AttributeSchema, ReadSchemaBackendHandler, Schema},
    model,
    sql_backend_handler::SqlBackendHandler,
};
use async_trait::async_trait;
use sea_orm::{DatabaseTransaction, EntityTrait, QueryOrder, TransactionTrait};

#[async_trait]
impl ReadSchemaBackendHandler for SqlBackendHandler {
    async fn get_schema(&self) -> Result<Schema> {
        Ok(self
            .sql_pool
            .transaction::<_, Schema, DomainError>(|transaction| {
                Box::pin(async move { Self::get_schema_with_transaction(transaction).await })
            })
            .await?)
    }
}

impl SqlBackendHandler {
    pub(crate) async fn get_schema_with_transaction(
        transaction: &DatabaseTransaction,
    ) -> Result<Schema> {
        Ok(Schema {
            user_attributes: AttributeList {
                attributes: Self::get_user_attributes(transaction).await?,
            },
            group_attributes: AttributeList {
                attributes: Self::get_group_attributes(transaction).await?,
            },
        })
    }

    async fn get_user_attributes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<AttributeSchema>> {
        Ok(model::UserAttributeSchema::find()
            .order_by_asc(model::UserAttributeSchemaColumn::AttributeName)
            .all(transaction)
            .await?
            .into_iter()
            .map(|m| m.into())
            .collect())
    }

    async fn get_group_attributes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<AttributeSchema>> {
        Ok(model::GroupAttributeSchema::find()
            .order_by_asc(model::GroupAttributeSchemaColumn::AttributeName)
            .all(transaction)
            .await?
            .into_iter()
            .map(|m| m.into())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        handler::AttributeList, sql_backend_handler::tests::*, types::AttributeType,
    };
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_default_schema() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            fixture.handler.get_schema().await.unwrap(),
            Schema {
                user_attributes: AttributeList {
                    attributes: vec![
                        AttributeSchema {
                            name: "avatar".to_owned(),
                            attribute_type: AttributeType::JpegPhoto,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                        },
                        AttributeSchema {
                            name: "first_name".to_owned(),
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                        },
                        AttributeSchema {
                            name: "last_name".to_owned(),
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                        }
                    ]
                },
                group_attributes: AttributeList {
                    attributes: Vec::new()
                }
            }
        );
    }
}
