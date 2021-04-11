use sea_query::*;
use sqlx::any::AnyPool;

#[derive(Iden)]
pub enum Users {
    Table,
    UserId,
    Email,
    DisplayName,
    FirstName,
    LastName,
    Avatar,
    CreationDate,
    Password,
    TotpSecret,
    MfaType,
}

#[derive(Iden)]
pub enum Groups {
    Table,
    GroupId,
    DisplayName,
}

#[derive(Iden)]
pub enum Memberships {
    Table,
    UserId,
    GroupId,
}

pub async fn init_table(pool: &AnyPool) -> sqlx::Result<()> {
    // SQLite needs this pragma to be turned on. Other DB might not understand this, so ignore the
    // error.
    let _ = sqlx::query("PRAGMA foreign_keys = ON").execute(pool).await;
    sqlx::query(
        &Table::create()
            .table(Users::Table)
            .create_if_not_exists()
            .col(
                ColumnDef::new(Users::UserId)
                    .string_len(255)
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(Users::Email).string_len(255).not_null())
            .col(
                ColumnDef::new(Users::DisplayName)
                    .string_len(255)
                    .not_null(),
            )
            .col(ColumnDef::new(Users::FirstName).string_len(255).not_null())
            .col(ColumnDef::new(Users::LastName).string_len(255).not_null())
            .col(ColumnDef::new(Users::Avatar).binary())
            .col(ColumnDef::new(Users::CreationDate).date_time().not_null())
            .col(ColumnDef::new(Users::Password).string_len(255).not_null())
            .col(ColumnDef::new(Users::TotpSecret).string_len(64))
            .col(ColumnDef::new(Users::MfaType).string_len(64))
            .to_string(MysqlQueryBuilder),
    )
    .execute(pool)
    .await?;
    sqlx::query(
        &Table::create()
            .table(Groups::Table)
            .create_if_not_exists()
            .col(
                ColumnDef::new(Groups::GroupId)
                    .integer()
                    .not_null()
                    .auto_increment()
                    .primary_key(),
            )
            .col(
                ColumnDef::new(Groups::DisplayName)
                    .string_len(255)
                    .not_null(),
            )
            .to_string(MysqlQueryBuilder),
    )
    .execute(pool)
    .await?;
    sqlx::query(
        &Table::create()
            .table(Memberships::Table)
            .create_if_not_exists()
            .col(
                ColumnDef::new(Memberships::UserId)
                    .string_len(255)
                    .not_null()
                    .primary_key(),
            )
            .col(
                ColumnDef::new(Memberships::GroupId)
                    .integer()
                    .not_null()
                    .auto_increment(),
            )
            .foreign_key(
                ForeignKey::create()
                    .name("MembershipUserForeignKey")
                    .table(Memberships::Table, Users::Table)
                    .col(Memberships::UserId, Users::UserId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .foreign_key(
                ForeignKey::create()
                    .name("MembershipGroupForeignKey")
                    .table(Memberships::Table, Groups::Table)
                    .col(Memberships::GroupId, Groups::GroupId)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            )
            .to_string(MysqlQueryBuilder),
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Column, Row};

    #[actix_rt::test]
    async fn test_init_table() {
        let sql_pool = sqlx::any::AnyPoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_table(&sql_pool).await.unwrap();
        sqlx::query(r#"INSERT INTO users
      (user_id, email, display_name, first_name, last_name, creation_date, password)
      VALUES ("bôb", "böb@bob.bob", "Bob Bobbersön", "Bob", "Bobberson", CURRENT_TIMESTAMP, "bob00")"#).execute(&sql_pool).await.unwrap();
        let row = sqlx::query(r#"SELECT display_name FROM users WHERE user_id = "bôb""#)
            .fetch_one(&sql_pool)
            .await
            .unwrap();
        assert_eq!(row.column(0).name(), "display_name");
        assert_eq!(row.get::<String, _>("display_name"), "Bob Bobbersön");
    }

    #[actix_rt::test]
    async fn test_already_init_table() {
        let sql_pool = sqlx::any::AnyPoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_table(&sql_pool).await.unwrap();
        init_table(&sql_pool).await.unwrap();
    }
}
