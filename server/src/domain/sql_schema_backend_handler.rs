use crate::domain::{
    error::{DomainError, Result},
    handler::{
        AttributeList, AttributeSchema, CreateAttributeRequest, ReadSchemaBackendHandler, Schema,
        SchemaBackendHandler,
    },
    model,
    sql_backend_handler::SqlBackendHandler,
    types::AttributeName,
};
use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, DatabaseTransaction, EntityTrait, QueryOrder, Set, TransactionTrait,
};

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

#[async_trait]
impl SchemaBackendHandler for SqlBackendHandler {
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        let new_attribute = model::user_attribute_schema::ActiveModel {
            attribute_name: Set(request.name),
            attribute_type: Set(request.attribute_type),
            is_list: Set(request.is_list),
            is_user_visible: Set(request.is_visible),
            is_user_editable: Set(request.is_editable),
            is_hardcoded: Set(false),
        };
        new_attribute.insert(&self.sql_pool).await?;
        Ok(())
    }

    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        let new_attribute = model::group_attribute_schema::ActiveModel {
            attribute_name: Set(request.name),
            attribute_type: Set(request.attribute_type),
            is_list: Set(request.is_list),
            is_group_visible: Set(request.is_visible),
            is_group_editable: Set(request.is_editable),
            is_hardcoded: Set(false),
        };
        new_attribute.insert(&self.sql_pool).await?;
        Ok(())
    }

    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()> {
        model::UserAttributeSchema::delete_by_id(name.clone())
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }

    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()> {
        model::GroupAttributeSchema::delete_by_id(name.clone())
            .exec(&self.sql_pool)
            .await?;
        Ok(())
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
                            name: "avatar".into(),
                            attribute_type: AttributeType::JpegPhoto,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                        },
                        AttributeSchema {
                            name: "first_name".into(),
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                        },
                        AttributeSchema {
                            name: "last_name".into(),
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

    #[tokio::test]
    async fn test_user_attribute_add_and_delete() {
        let fixture = TestFixture::new().await;
        let new_attribute = CreateAttributeRequest {
            name: "new_attribute".into(),
            attribute_type: AttributeType::Integer,
            is_list: true,
            is_visible: false,
            is_editable: false,
        };
        fixture
            .handler
            .add_user_attribute(new_attribute)
            .await
            .unwrap();
        let expected_value = AttributeSchema {
            name: "new_attribute".into(),
            attribute_type: AttributeType::Integer,
            is_list: true,
            is_visible: false,
            is_editable: false,
            is_hardcoded: false,
        };
        assert!(fixture
            .handler
            .get_schema()
            .await
            .unwrap()
            .user_attributes
            .attributes
            .contains(&expected_value));
        fixture
            .handler
            .delete_user_attribute(&"new_attribute".into())
            .await
            .unwrap();
        assert!(!fixture
            .handler
            .get_schema()
            .await
            .unwrap()
            .user_attributes
            .attributes
            .contains(&expected_value));
    }

    #[tokio::test]
    async fn test_group_attribute_add_and_delete() {
        let fixture = TestFixture::new().await;
        let new_attribute = CreateAttributeRequest {
            name: "NeW_aTTribute".into(),
            attribute_type: AttributeType::JpegPhoto,
            is_list: false,
            is_visible: true,
            is_editable: false,
        };
        fixture
            .handler
            .add_group_attribute(new_attribute)
            .await
            .unwrap();
        let expected_value = AttributeSchema {
            name: "new_attribute".into(),
            attribute_type: AttributeType::JpegPhoto,
            is_list: false,
            is_visible: true,
            is_editable: false,
            is_hardcoded: false,
        };
        assert!(fixture
            .handler
            .get_schema()
            .await
            .unwrap()
            .group_attributes
            .attributes
            .contains(&expected_value));
        fixture
            .handler
            .delete_group_attribute(&"new_attriBUte".into())
            .await
            .unwrap();
        assert!(!fixture
            .handler
            .get_schema()
            .await
            .unwrap()
            .group_attributes
            .attributes
            .contains(&expected_value));
    }
}
