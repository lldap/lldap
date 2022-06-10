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
        crate::domain::handler::Uuid::try_from($s).unwrap()
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

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub user_id: UserId,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    // pub avatar: ?,
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
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct UpdateUserRequest {
    // Same fields as CreateUserRequest, but no with an extra layer of Option.
    pub user_id: UserId,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
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

#[derive(Debug, Clone, PartialEq)]
pub struct UserAndGroups {
    pub user: User,
    pub groups: Option<Vec<GroupDetails>>,
}

#[async_trait]
pub trait BackendHandler: Clone + Send {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>>;
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
    async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
    async fn delete_user(&self, user_id: &UserId) -> Result<()>;
    async fn create_group(&self, group_name: &str) -> Result<GroupId>;
    async fn delete_group(&self, group_id: GroupId) -> Result<()>;
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
}

#[cfg(test)]
mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {
        async fn list_users(&self, filters: Option<UserRequestFilter>, get_groups: bool) -> Result<Vec<UserAndGroups>>;
        async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
        async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
        async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
        async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
        async fn delete_user(&self, user_id: &UserId) -> Result<()>;
        async fn create_group(&self, group_name: &str) -> Result<GroupId>;
        async fn delete_group(&self, group_id: GroupId) -> Result<()>;
        async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
        async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
        async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    }
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
}
