use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::domain::types::LdapObjectClass;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "group_object_classes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub lower_object_class: String,
    pub object_class: LdapObjectClass,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for LdapObjectClass {
    fn from(value: Model) -> Self {
        value.object_class
    }
}
