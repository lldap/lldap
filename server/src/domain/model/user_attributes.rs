use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::domain::types::{AttributeValue, Serialized, UserId};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "user_attributes")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "user_attribute_user_id"
    )]
    pub user_id: UserId,
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "user_attribute_name"
    )]
    pub attribute_name: String,
    #[sea_orm(column_name = "user_attribute_value")]
    pub value: Serialized,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::UserId",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Users,
    #[sea_orm(
        belongs_to = "super::user_attribute_schema::Entity",
        from = "Column::AttributeName",
        to = "super::user_attribute_schema::Column::AttributeName",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    UserAttributeSchema,
}

impl Related<super::User> for Entity {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl Related<super::UserAttributeSchema> for Entity {
    fn to() -> RelationDef {
        Relation::UserAttributeSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for AttributeValue {
    fn from(
        Model {
            user_id: _,
            attribute_name,
            value,
        }: Model,
    ) -> Self {
        Self {
            name: attribute_name,
            value,
        }
    }
}
