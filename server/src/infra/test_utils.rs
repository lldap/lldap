use crate::domain::{error::Result, handler::*, opaque_handler::*};
use lldap_domain::types::*;

use async_trait::async_trait;
use std::collections::HashSet;

mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl LoginHandler for TestBackendHandler {
        async fn bind(&self, request: BindRequest) -> Result<()>;
    }
    #[async_trait]
    impl GroupListerBackendHandler for TestBackendHandler {
        async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
    }
    #[async_trait]
    impl GroupBackendHandler for TestBackendHandler {
        async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
        async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
        async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId>;
        async fn delete_group(&self, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl UserListerBackendHandler for TestBackendHandler {
        async fn list_users(&self, filters: Option<UserRequestFilter>, get_groups: bool) -> Result<Vec<UserAndGroups>>;
    }
    #[async_trait]
    impl UserBackendHandler for TestBackendHandler {
        async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
        async fn delete_user(&self, user_id: &UserId) -> Result<()>;
        async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
        async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
        async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl ReadSchemaBackendHandler for TestBackendHandler {
        async fn get_schema(&self) -> Result<Schema>;
    }
    #[async_trait]
    impl SchemaBackendHandler for TestBackendHandler {
        async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
        async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
        async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()>;
        async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()>;
        async fn add_user_object_class(&self, request: &LdapObjectClass) -> Result<()>;
        async fn add_group_object_class(&self, request: &LdapObjectClass) -> Result<()>;
        async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
        async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {}
    #[async_trait]
    impl OpaqueHandler for TestBackendHandler {
        async fn login_start(
            &self,
            request: login::ClientLoginStartRequest
        ) -> Result<login::ServerLoginStartResponse>;
        async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId>;
        async fn registration_start(
            &self,
            request: registration::ClientRegistrationStartRequest
        ) -> Result<registration::ServerRegistrationStartResponse>;
        async fn registration_finish(
            &self,
            request: registration::ClientRegistrationFinishRequest
        ) -> Result<()>;
    }
}

pub fn setup_default_schema(mock: &mut MockTestBackendHandler) {
    mock.expect_get_schema().returning(|| {
        Ok(Schema {
            user_attributes: AttributeList {
                attributes: vec![
                    AttributeSchema {
                        name: "avatar".into(),
                        attribute_type: AttributeType::JpegPhoto,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "first_name".into(),
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                    AttributeSchema {
                        name: "last_name".into(),
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    },
                ],
            },
            group_attributes: AttributeList {
                attributes: Vec::new(),
            },
            extra_user_object_classes: vec![LdapObjectClass::from("customUserClass")],
            extra_group_object_classes: Vec::new(),
        })
    });
}
