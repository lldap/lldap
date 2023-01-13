use super::{
    error::Result,
    types::{
        Group, GroupDetails, GroupId, JpegPhoto, User, UserAndGroups, UserColumn, UserId, Uuid,
    },
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct BindRequest {
    pub name: UserId,
    pub password: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub enum UserRequestFilter {
    And(Vec<UserRequestFilter>),
    Or(Vec<UserRequestFilter>),
    Not(Box<UserRequestFilter>),
    UserId(UserId),
    Equality(UserColumn, String),
    // Check if a user belongs to a group identified by name.
    MemberOf(String),
    // Same, by id.
    MemberOfId(GroupId),
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub enum GroupRequestFilter {
    And(Vec<GroupRequestFilter>),
    Or(Vec<GroupRequestFilter>),
    Not(Box<GroupRequestFilter>),
    DisplayName(String),
    Uuid(Uuid),
    GroupId(GroupId),
    // Check if the group contains a user identified by uid.
    Member(UserId),
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct CreateUserRequest {
    // Same fields as User, but no creation_date, and with password.
    pub user_id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<JpegPhoto>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct UpdateUserRequest {
    // Same fields as CreateUserRequest, but no with an extra layer of Option.
    pub user_id: UserId,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<JpegPhoto>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct UpdateGroupRequest {
    pub group_id: GroupId,
    pub display_name: Option<String>,
}

#[async_trait]
pub trait LoginHandler: Clone + Send {
    async fn bind(&self, request: BindRequest) -> Result<()>;
}

#[async_trait]
pub trait GroupBackendHandler {
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
    async fn create_group(&self, group_name: &str) -> Result<GroupId>;
    async fn delete_group(&self, group_id: GroupId) -> Result<()>;
}

#[async_trait]
pub trait UserBackendHandler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>>;
    async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
    async fn delete_user(&self, user_id: &UserId) -> Result<()>;
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
}

#[async_trait]
pub trait BackendHandler: Clone + Send + GroupBackendHandler + UserBackendHandler {}

#[cfg(test)]
mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl GroupBackendHandler for TestBackendHandler {
        async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
        async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
        async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
        async fn create_group(&self, group_name: &str) -> Result<GroupId>;
        async fn delete_group(&self, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl UserBackendHandler for TestBackendHandler {
        async fn list_users(&self, filters: Option<UserRequestFilter>, get_groups: bool) -> Result<Vec<UserAndGroups>>;
        async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
        async fn delete_user(&self, user_id: &UserId) -> Result<()>;
        async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
        async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
        async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {}
    #[async_trait]
    impl LoginHandler for TestBackendHandler {
        async fn bind(&self, request: BindRequest) -> Result<()>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_uuid_time() {
        use chrono::prelude::*;
        let user_id = "bob";
        let date1 = Utc
            .with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
            .unwrap()
            .naive_utc();
        let date2 = Utc
            .with_ymd_and_hms(2014, 7, 8, 9, 10, 12)
            .unwrap()
            .naive_utc();
        assert_ne!(
            Uuid::from_name_and_date(user_id, &date1),
            Uuid::from_name_and_date(user_id, &date2)
        );
    }

    #[test]
    fn test_jpeg_try_from_bytes() {
        let base64_raw = "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCADqATkDASIAAhEBAxEB/8QAFwABAQEBAAAAAAAAAAAAAAAAAAECA//EACQQAQEBAAIBBAMBAQEBAAAAAAABESExQQISUXFhgZGxocHw/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAH/xAAWEQEBAQAAAAAAAAAAAAAAAAAAEQH/2gAMAwEAAhEDEQA/AMriLyCKgg1gQwCgs4FTMOdutepjQak+FzMSVqgxZdRdPPIIvH5WzzGdBriphtTeAXg2ZjKA1pqKDUGZca3foBek8gFv8Ie3fKdA1qb8s7hoL6eLVt51FsAnql3Ut1M7AWbflLMDkEMX/F6/YjK/pADFQAUNA6alYagKk72m/j9p4Bq2fDDSYKLNXPNLoHE/NT6RYC31cJxZ3yWVM+aBYi/S2ZgiAsnYJx5D21vPmqrm3PTfpQQwyAC8JZvSKDni41ZrMuUVVl+Uz9w9v/1QWrZsZ5nFPHYH+JZyureQSF5M+fJ0CAfwRAVRBQA1DAWVUayoJUWoDpsxntPsueBV4+VxhdyAtv8AjOLGpIDMLbeGvbF4iozJfr/WukAVABAXAQXEAAASzVAZdO2WNordm+emFl7XcQSNZiFtv0C9w90nhJf4mA1u+GcJFwIyAqL/AOovwgGNfSRqdIrNa29M0gKCAojU9PAMjWXpckEJFNFEAAXEUBABYz6rZ0ureQc9vyt9XxDF2QAXtABcQAs0AZywkvluJbyipifas52DcyxjlZweAO0xri/hc+wZOEKIu6nSyeToVZyWXwvCg53gW81QQ7aTNAn5dGZJPs1UXURQAUEMCXQLZE93PRZ5hPTgNMrbIzKCm52LZwCs+2M8w2g3sjPuZAXb4IsMAUACzVUGM4/K+md6vEXUUyM5PDR0IxYe6ramih0VNBrS4xoqN8Q1BFQk3yqyAsioioAAKgDSJL4/jQIn5igLrPqtOuf6oOaxbMoAltUAhhIoJiiggrPu+AaOIxtAX3JbaAIaLwi4t9X4T3fg2AFtqcrUUarP20zUDAmqoE0WRBZPNVUVEAAAAVAC8kvih2DSKxOdBqs7Z0l0gI0mKAC4AuHE7ZtBriM+744QAAAAABAFsveIttBICyaikvy1+r/Cen5rWQHIBQa4rIDRqSl5qDWqziqgAAAATA7BpGdqXb2C2+J/UgAtRQBSQtkBWb6vhLbQAAAAAEBRAAAAAUbm+GZNdPxAP+ql2Tjwx7/wIgZ8iKvBk+CJoCXii9gaqZ/qqihAAAEVABGkBFUwBftNkZ3QW34QAAABFAQAVAAAAAARVkl8gs/43sk1jL45LvHArepk+E9XTG35oLqsmIKmLAEygKg0y1AFQBUXwgAAAoBC34S3UAAABAVAAAAAABAUQAVABdRQa1PcYyit2z58M8C4ouM2NXpOEGeWtNZUatiAIoAKIoCoAoG4C9MW6dgIoAIAAAAAAACKWAgL0CAAAALiANCKioNLgM1CrLihmTafkt1EF3SZ5ZVUW4mnIKvAi5fhEURVDWVQBRAAAAAAAAQFRVyAyulgAqCKlF8IqLsEgC9mGoC+IusqCrv5ZEUVOk1RuJfwSLOOkGFi4XPCoYYrNiKauosBGi9ICstM1UAAAAAAFQ0VcTBAXUGgIqGoKhKAzRRUQUAwxoSrGRpkQA/qiosOL9oJptMRRVZa0VUqSiChE6BqMgCwqKqIogAIAqKCKgKoogg0lBFuIKgAAAKNRlf2gqsftsEtZWoAAqAACKoMqAAeSoqp39kL2AqLOlE8rEBFQARYALhigrNC9gGmooLp4TweEQFFBFAECgIoAu0ifIAqAAA//9k=";
        let base64_jpeg = base64::decode(base64_raw).unwrap();
        JpegPhoto::try_from(base64_jpeg).unwrap();
    }
}
