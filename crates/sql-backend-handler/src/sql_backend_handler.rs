use crate::{password_service::PasswordService, sql_tables::DbConnection};
use async_trait::async_trait;
use lldap_auth::opaque::server::ServerSetup;
use lldap_domain_handlers::handler::BackendHandler;

#[derive(Clone)]
pub struct SqlBackendHandler {
    pub(crate) opaque_setup: ServerSetup,
    pub(crate) sql_pool: DbConnection,
    pub(crate) crypto_service: PasswordService,
    pub(crate) readonly: bool,
}

impl SqlBackendHandler {
    pub fn new(opaque_setup: ServerSetup, sql_pool: DbConnection, readonly: bool) -> Self {
        SqlBackendHandler {
            opaque_setup,
            sql_pool,
            crypto_service: PasswordService::new(),
            readonly,
        }
    }

    pub fn pool(&self) -> &DbConnection {
        &self.sql_pool
    }

    pub fn is_readonly(&self) -> bool {
        self.readonly
    }
}

#[async_trait]
impl BackendHandler for SqlBackendHandler {}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::sql_tables::init_table;
    use lldap_auth::{
        opaque::{self, server::generate_random_private_key},
        registration,
    };
    use lldap_domain::{
        requests::{CreateGroupRequest, CreateUserRequest},
        types::{Attribute as DomainAttribute, GroupId, UserId},
    };
    use lldap_domain_handlers::handler::{
        GroupBackendHandler, UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
    };
    use pretty_assertions::assert_eq;
    use sea_orm::Database;

    pub async fn get_in_memory_db() -> DbConnection {
        crate::logging::init_for_tests();
        let mut sql_opt = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        sql_opt
            .max_connections(1)
            .sqlx_logging(true)
            .sqlx_logging_level(log::LevelFilter::Debug);
        Database::connect(sql_opt).await.unwrap()
    }

    pub async fn get_initialized_db() -> DbConnection {
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        sql_pool
    }

    pub async fn insert_user(handler: &SqlBackendHandler, name: &str, pass: &str) {
        use lldap_opaque_handler::OpaqueHandler;
        insert_user_no_password(handler, name).await;
        let mut rng = rand::rngs::OsRng;
        let client_registration_start =
            opaque::client::registration::start_registration(pass.as_bytes(), &mut rng).unwrap();
        let response = handler
            .registration_start(registration::ClientRegistrationStartRequest {
                username: name.into(),
                registration_start_request: client_registration_start.message,
            })
            .await
            .unwrap();
        let registration_upload = opaque::client::registration::finish_registration(
            client_registration_start.state,
            response.registration_response,
            &mut rng,
        )
        .unwrap();
        handler
            .registration_finish(registration::ClientRegistrationFinishRequest {
                server_data: response.server_data,
                registration_upload: registration_upload.message,
            })
            .await
            .unwrap();
    }

    pub async fn insert_user_no_password(handler: &SqlBackendHandler, name: &str) {
        handler
            .create_user(CreateUserRequest {
                user_id: UserId::new(name),
                email: format!("{name}@bob.bob").into(),
                display_name: Some("display ".to_string() + name),
                attributes: vec![
                    DomainAttribute {
                        name: "first_name".into(),
                        value: ("first ".to_string() + name).into(),
                    },
                    DomainAttribute {
                        name: "last_name".into(),
                        value: ("last ".to_string() + name).into(),
                    },
                ],
            })
            .await
            .unwrap();
    }

    pub async fn insert_group(handler: &SqlBackendHandler, name: &str) -> GroupId {
        handler
            .create_group(CreateGroupRequest {
                display_name: name.into(),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    pub async fn insert_membership(handler: &SqlBackendHandler, group_id: GroupId, user_id: &str) {
        handler
            .add_user_to_group(&UserId::new(user_id), group_id)
            .await
            .unwrap();
    }

    pub async fn get_user_names(
        handler: &SqlBackendHandler,
        filters: Option<UserRequestFilter>,
    ) -> Vec<String> {
        handler
            .list_users(filters, false)
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.user.user_id.to_string())
            .collect::<Vec<_>>()
    }

    pub struct TestFixture {
        pub handler: SqlBackendHandler,
        pub groups: Vec<GroupId>,
    }

    impl TestFixture {
        pub async fn new() -> Self {
            let sql_pool = get_initialized_db().await;
            let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool, false);
            insert_user_no_password(&handler, "bob").await;
            insert_user_no_password(&handler, "patrick").await;
            insert_user_no_password(&handler, "John").await;
            insert_user_no_password(&handler, "NoGroup").await;
            let mut groups = vec![];
            groups.push(insert_group(&handler, "Best Group").await);
            groups.push(insert_group(&handler, "Worst Group").await);
            groups.push(insert_group(&handler, "Empty Group").await);
            insert_membership(&handler, groups[0], "bob").await;
            insert_membership(&handler, groups[0], "patrick").await;
            insert_membership(&handler, groups[1], "patrick").await;
            insert_membership(&handler, groups[1], "John").await;
            Self { handler, groups }
        }
    }

    #[tokio::test]
    async fn test_sql_injection() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool, false);
        let user_name = UserId::new(r#"bob"e"i'o;aü"#);
        insert_user_no_password(&handler, user_name.as_str()).await;
        {
            let users = handler
                .list_users(None, false)
                .await
                .unwrap()
                .into_iter()
                .map(|u| u.user.user_id)
                .collect::<Vec<_>>();

            assert_eq!(users, vec![user_name.clone()]);
            let user = handler.get_user_details(&user_name).await.unwrap();
            assert_eq!(user.user_id, user_name);
        }
    }
}
