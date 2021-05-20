use serde::{Deserialize, Serialize};
use chrono::prelude::*;
use std::collections::HashSet;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct BindRequest {
    pub name: String,
    pub password: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub enum RequestFilter {
    And(Vec<RequestFilter>),
    Or(Vec<RequestFilter>),
    Not(Box<RequestFilter>),
    Equality(String, String),
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct ListUsersRequest {
    pub filters: Option<RequestFilter>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(sqlx::FromRow))]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    // pub avatar: ?,
    pub creation_date: chrono::NaiveDateTime,
}

impl Default for User {
    fn default() -> Self {
        User {
            user_id: String::new(),
            email: String::new(),
            display_name: String::new(),
            first_name: String::new(),
            last_name: String::new(),
            creation_date: chrono::NaiveDateTime::from_timestamp(0, 0),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Group {
    pub display_name: String,
    pub users: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub exp: DateTime<Utc>,
    pub iat: DateTime<Utc>,
    pub user: String,
    pub groups: HashSet<String>,
}
