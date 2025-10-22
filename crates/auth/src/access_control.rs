use crate::types::UserId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Permission {
    Admin,
    PasswordManager,
    Readonly,
    Regular,
    UserManager,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResults {
    pub user: UserId,
    pub permission: Permission,
}

impl ValidationResults {
    #[cfg(feature = "test")]
    pub fn admin() -> Self {
        Self {
            user: UserId::new("admin"),
            permission: Permission::Admin,
        }
    }

    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.permission == Permission::Admin
    }

    #[must_use]
    pub fn is_user_manager(&self) -> bool {
        self.permission == Permission::Admin || self.permission == Permission::UserManager
    }

    #[must_use]
    pub fn can_read_all(&self) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::Readonly
            || self.permission == Permission::PasswordManager
            || self.permission == Permission::UserManager
    }

    #[must_use]
    pub fn can_read(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::PasswordManager
            || self.permission == Permission::Readonly
            || self.permission == Permission::UserManager
            || &self.user == user
    }

    #[must_use]
    pub fn can_change_password(&self, user: &UserId, user_is_admin: bool, user_is_user_manager: bool) -> bool {
        self.permission == Permission::Admin
            || (self.permission == Permission::PasswordManager && !user_is_admin)
            || (self.permission == Permission::PasswordManager && !user_is_admin && !user_is_user_manager)
            || (self.permission == Permission::UserManager && !user_is_admin && !user_is_user_manager)
            || &self.user == user
    }

    #[must_use]
    pub fn can_write(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::UserManager
            || &self.user == user
    }
}
