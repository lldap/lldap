use sea_orm::{
    sea_query::{self, ColumnDef, Index, Table},
    ConnectionTrait, DatabaseTransaction, DbErr, DeriveIden,
};

use serde::{Deserialize, Serialize};

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum PluginKeyValues {
    Table,
    PluginKeyScope,
    PluginKey,
    PluginKeyValue,
}

pub async fn create_plugin_kv_table(transaction: &DatabaseTransaction) -> Result<(), DbErr> {
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(PluginKeyValues::Table)
                    .col(
                        ColumnDef::new(PluginKeyValues::PluginKeyScope)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PluginKeyValues::PluginKey)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PluginKeyValues::PluginKeyValue)
                            .blob(sea_query::BlobSize::Long)
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(PluginKeyValues::PluginKeyScope)
                            .col(PluginKeyValues::PluginKey),
                    ),
            ),
        )
        .await?;
    Ok(())
}
