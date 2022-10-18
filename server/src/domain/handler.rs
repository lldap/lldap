use super::error::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(
    PartialEq, Hash, Eq, Clone, Debug, Default, Serialize, Deserialize, sqlx::FromRow, sqlx::Type,
)]
#[serde(try_from = "&str")]
#[sqlx(transparent)]
pub struct Uuid(String);

impl Uuid {
    pub fn from_name_and_date(name: &str, creation_date: &chrono::DateTime<chrono::Utc>) -> Self {
        Uuid(
            uuid::Uuid::new_v3(
                &uuid::Uuid::NAMESPACE_X500,
                &[name.as_bytes(), creation_date.to_rfc3339().as_bytes()].concat(),
            )
            .to_string(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl<'a> std::convert::TryFrom<&'a str> for Uuid {
    type Error = anyhow::Error;
    fn try_from(s: &'a str) -> anyhow::Result<Self> {
        Ok(Uuid(uuid::Uuid::parse_str(s)?.to_string()))
    }
}

impl std::string::ToString for Uuid {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

#[cfg(test)]
#[macro_export]
macro_rules! uuid {
    ($s:literal) => {
        $crate::domain::handler::Uuid::try_from($s).unwrap()
    };
}

#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize, Deserialize, sqlx::Type)]
#[serde(from = "String")]
#[sqlx(transparent)]
pub struct UserId(String);

impl UserId {
    pub fn new(user_id: &str) -> Self {
        Self(user_id.to_lowercase())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self::new(&s)
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct JpegPhoto(#[serde(with = "serde_bytes")] Vec<u8>);

impl From<JpegPhoto> for sea_query::Value {
    fn from(photo: JpegPhoto) -> Self {
        photo.0.into()
    }
}

impl From<&JpegPhoto> for sea_query::Value {
    fn from(photo: &JpegPhoto) -> Self {
        photo.0.as_slice().into()
    }
}

impl TryFrom<Vec<u8>> for JpegPhoto {
    type Error = anyhow::Error;
    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        // Confirm that it's a valid Jpeg, then store only the bytes.
        image::io::Reader::with_format(
            std::io::Cursor::new(bytes.as_slice()),
            image::ImageFormat::Jpeg,
        )
        .decode()?;
        Ok(JpegPhoto(bytes))
    }
}

impl TryFrom<String> for JpegPhoto {
    type Error = anyhow::Error;
    fn try_from(string: String) -> anyhow::Result<Self> {
        // The String format is in base64.
        Self::try_from(base64::decode(string.as_str())?)
    }
}

impl From<&JpegPhoto> for String {
    fn from(val: &JpegPhoto) -> Self {
        base64::encode(&val.0)
    }
}

impl JpegPhoto {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        use image::{ImageOutputFormat, Rgb, RgbImage};
        let img = RgbImage::from_fn(32, 32, |x, y| {
            if (x + y) % 2 == 0 {
                Rgb([0, 0, 0])
            } else {
                Rgb([255, 255, 255])
            }
        });
        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut bytes),
            ImageOutputFormat::Jpeg(0),
        )
        .unwrap();
        Self(bytes)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub user_id: UserId,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub avatar: JpegPhoto,
    pub creation_date: chrono::DateTime<chrono::Utc>,
    pub uuid: Uuid,
}

#[cfg(test)]
impl Default for User {
    fn default() -> Self {
        use chrono::TimeZone;
        let epoch = chrono::Utc.timestamp(0, 0);
        User {
            user_id: UserId::default(),
            email: String::new(),
            display_name: String::new(),
            first_name: String::new(),
            last_name: String::new(),
            avatar: JpegPhoto::default(),
            creation_date: epoch,
            uuid: Uuid::from_name_and_date("", &epoch),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub display_name: String,
    pub creation_date: chrono::DateTime<chrono::Utc>,
    pub uuid: Uuid,
    pub users: Vec<UserId>,
}

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
    Equality(String, String),
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct GroupId(pub i32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::FromRow)]
pub struct GroupDetails {
    pub group_id: GroupId,
    pub display_name: String,
    pub creation_date: chrono::DateTime<chrono::Utc>,
    pub uuid: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAndGroups {
    pub user: User,
    pub groups: Option<Vec<GroupDetails>>,
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
        let date1 = Utc.ymd(2014, 7, 8).and_hms(9, 10, 11);
        let date2 = Utc.ymd(2014, 7, 8).and_hms(9, 10, 12);
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
