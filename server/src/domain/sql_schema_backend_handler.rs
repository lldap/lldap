use crate::domain::{
    error::Result,
    handler::{AttributeSchema, Schema, SchemaBackendHandler},
    model,
    sql_backend_handler::SqlBackendHandler,
};
use async_trait::async_trait;
use sea_orm::{EntityTrait, QueryOrder};

#[async_trait]
impl SchemaBackendHandler for SqlBackendHandler {
    async fn get_schema(&self) -> Result<Schema> {
        Ok(Schema {
            user_attributes: self.get_user_attributes().await?,
            group_attributes: self.get_group_attributes().await?,
        })
    }
}

impl SqlBackendHandler {
    async fn get_user_attributes(&self) -> Result<Vec<AttributeSchema>> {
        Ok(model::UserAttributeSchema::find()
            .order_by_asc(model::UserAttributeSchemaColumn::AttributeName)
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|m| m.into())
            .collect())
    }

    async fn get_group_attributes(&self) -> Result<Vec<AttributeSchema>> {
        Ok(model::GroupAttributeSchema::find()
            .order_by_asc(model::GroupAttributeSchemaColumn::AttributeName)
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|m| m.into())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{sql_backend_handler::tests::*, types::AttributeType};

    #[tokio::test]
    async fn test_default_schema() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            fixture.handler.get_schema().await.unwrap(),
            Schema {
                user_attributes: vec![
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
                ],
                group_attributes: Vec::new()
            }
        );
    }
}
