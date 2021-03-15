use sqlx::any::AnyPool;

pub async fn init_table(pool: &AnyPool) -> sqlx::Result<()> {
    // SQLite needs this pragma to be turned on. Other DB might not understand this, so ignore the
    // error.
    let _ = sqlx::query("PRAGMA foreign_keys = ON").execute(pool).await;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
      user_id NVARCHAR(255) PRIMARY KEY,
      email NVARCHAR(255) NOT NULL,
      display_name NVARCHAR(255) NOT NULL,
      first_name NVARCHAR(255) NOT NULL,
      last_name NVARCHAR(255) NOT NULL,
      avatar Blob,
      creation_date DateTime NOT NULL,
      password NVARCHAR(255) NOT NULL,
      totp_secret VARCHAR(64),
      mfa_type Text
      )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS groups (
      group_id integer PRIMARY KEY AUTOINCREMENT,
      display_name NVARCHAR(255) NOT NULL
      )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS membership (
      user_id NVARCHAR(255) PRIMARY KEY,
      group_id integer NOT NULL,
      FOREIGN KEY (user_id)
        REFERENCES users (user_id),
      FOREIGN KEY (group_id)
        REFERENCES groups (group_id)
      )",
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
