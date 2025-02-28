use std::cmp::Ordering;

use base64::Engine;
use chrono::{NaiveDateTime, TimeZone};
use lldap_auth::types::CaseInsensitiveString;
use sea_orm::{
    entity::IntoActiveValue,
    sea_query::{value::ValueType, ArrayType, BlobSize, ColumnType, Nullable, ValueTypeErr},
    DbErr, DeriveValueType, QueryResult, TryFromU64, TryGetError, TryGetable, Value,
};
use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr};

pub use lldap_auth::types::UserId;

#[derive(
    PartialEq,
    Hash,
    Eq,
    Clone,
    Default,
    Serialize,
    Deserialize,
    DeriveValueType,
    derive_more::Debug,
    derive_more::Display,
)]
#[serde(try_from = "&str")]
#[sea_orm(column_type = "String(Some(36))")]
#[debug(r#""{_0}""#)]
#[display("{_0}")]
pub struct Uuid(String);

impl Uuid {
    pub fn from_name_and_date(name: &str, creation_date: &NaiveDateTime) -> Self {
        Uuid(
            uuid::Uuid::new_v3(
                &uuid::Uuid::NAMESPACE_X500,
                &[
                    name.as_bytes(),
                    chrono::Utc
                        .from_utc_datetime(creation_date)
                        .to_rfc3339()
                        .as_bytes(),
                ]
                .concat(),
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

#[cfg(feature = "test")]
#[macro_export]
macro_rules! uuid {
    ($s:literal) => {
        <lldap_domain::types::Uuid as std::convert::TryFrom<_>>::try_from($s).unwrap()
    };
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, DeriveValueType)]
#[sea_orm(column_type = "Binary(BlobSize::Long)", array_type = "Bytes")]
pub struct Serialized(Vec<u8>);

const SERIALIZED_I64_LEN: usize = 8;

impl std::fmt::Debug for Serialized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Serialized")
            .field(
                &self
                    .convert_to()
                    .and_then(|s| {
                        String::from_utf8(s)
                            .map_err(|_| Box::new(bincode::ErrorKind::InvalidCharEncoding))
                    })
                    .or_else(|e| {
                        if self.0.len() == SERIALIZED_I64_LEN {
                            self.convert_to::<i64>()
                                .map(|i| i.to_string())
                                .map_err(|_| Box::new(bincode::ErrorKind::InvalidCharEncoding))
                        } else {
                            Err(e)
                        }
                    })
                    .unwrap_or_else(|_| {
                        format!("hash: {:#016X}", {
                            let mut hasher = std::collections::hash_map::DefaultHasher::new();
                            std::hash::Hash::hash(&self.0, &mut hasher);
                            std::hash::Hasher::finish(&hasher)
                        })
                    }),
            )
            .finish()
    }
}

impl<'a, T: Serialize + ?Sized> From<&'a T> for Serialized {
    fn from(t: &'a T) -> Self {
        Self(bincode::serialize(&t).unwrap())
    }
}

impl Serialized {
    pub fn convert_to<'a, T: Deserialize<'a>>(&'a self) -> bincode::Result<T> {
        bincode::deserialize(&self.0)
    }

    pub fn unwrap<'a, T: Deserialize<'a>>(&'a self) -> T {
        self.convert_to().unwrap()
    }

    pub fn expect<'a, T: Deserialize<'a>>(&'a self, message: &str) -> T {
        self.convert_to().expect(message)
    }
}

impl From<AttributeValue> for Serialized {
    fn from(val: AttributeValue) -> Serialized {
        match &val {
            AttributeValue::String(Cardinality::Singleton(s)) => Serialized::from(s),
            AttributeValue::String(Cardinality::Unbounded(l)) => Serialized::from(l),
            AttributeValue::Integer(Cardinality::Singleton(i)) => Serialized::from(i),
            AttributeValue::Integer(Cardinality::Unbounded(l)) => Serialized::from(l),
            AttributeValue::JpegPhoto(Cardinality::Singleton(p)) => Serialized::from(p),
            AttributeValue::JpegPhoto(Cardinality::Unbounded(l)) => Serialized::from(l),
            AttributeValue::DateTime(Cardinality::Singleton(dt)) => Serialized::from(dt),
            AttributeValue::DateTime(Cardinality::Unbounded(l)) => Serialized::from(l),
        }
    }
}

fn compare_str_case_insensitive(s1: &str, s2: &str) -> Ordering {
    let mut it_1 = s1.chars().flat_map(|c| c.to_lowercase());
    let mut it_2 = s2.chars().flat_map(|c| c.to_lowercase());
    loop {
        match (it_1.next(), it_2.next()) {
            (Some(c1), Some(c2)) => {
                let o = c1.cmp(&c2);
                if o != Ordering::Equal {
                    return o;
                }
            }
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

macro_rules! make_case_insensitive_comparable_string {
    ($c:ident) => {
        #[derive(
            Clone,
            Default,
            Serialize,
            Deserialize,
            DeriveValueType,
            derive_more::Debug,
            derive_more::Display,
        )]
        #[debug(r#""{_0}""#)]
        #[display("{_0}")]
        pub struct $c(String);

        impl PartialEq for $c {
            fn eq(&self, other: &Self) -> bool {
                compare_str_case_insensitive(&self.0, &other.0) == Ordering::Equal
            }
        }

        impl Eq for $c {}

        impl PartialOrd for $c {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $c {
            fn cmp(&self, other: &Self) -> Ordering {
                compare_str_case_insensitive(&self.0, &other.0)
            }
        }

        impl std::hash::Hash for $c {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.0.to_lowercase().hash(state)
            }
        }

        impl $c {
            pub fn new(raw: &str) -> Self {
                Self(raw.to_owned())
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl From<String> for $c {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $c {
            fn from(s: &str) -> Self {
                Self::new(s)
            }
        }

        impl From<&$c> for Value {
            fn from(user_id: &$c) -> Self {
                user_id.as_str().into()
            }
        }

        impl TryFromU64 for $c {
            fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
                Err(DbErr::ConvertFromU64("$c cannot be constructed from u64"))
            }
        }
    };
}

#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Debug,
    Default,
    Hash,
    Serialize,
    Deserialize,
    DeriveValueType,
)]
#[serde(from = "CaseInsensitiveString")]
pub struct AttributeName(CaseInsensitiveString);

impl AttributeName {
    pub fn new(s: &str) -> Self {
        s.into()
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn into_string(self) -> String {
        self.0.into_string()
    }
}
impl<T> From<T> for AttributeName
where
    T: Into<CaseInsensitiveString>,
{
    fn from(s: T) -> Self {
        Self(s.into())
    }
}
impl std::fmt::Display for AttributeName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}
impl From<&AttributeName> for Value {
    fn from(attribute_name: &AttributeName) -> Self {
        attribute_name.as_str().into()
    }
}
impl TryFromU64 for AttributeName {
    fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(
            "AttributeName cannot be constructed from u64",
        ))
    }
}

make_case_insensitive_comparable_string!(LdapObjectClass);
make_case_insensitive_comparable_string!(Email);
make_case_insensitive_comparable_string!(GroupName);

impl AsRef<GroupName> for GroupName {
    fn as_ref(&self) -> &GroupName {
        self
    }
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize, DeriveValueType, Hash)]
#[sea_orm(column_type = "Binary(BlobSize::Long)", array_type = "Bytes")]
pub struct JpegPhoto(#[serde(with = "serde_bytes")] Vec<u8>);

impl From<&JpegPhoto> for Value {
    fn from(photo: &JpegPhoto) -> Self {
        photo.0.as_slice().into()
    }
}

impl TryFrom<&[u8]> for JpegPhoto {
    type Error = anyhow::Error;
    fn try_from(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.is_empty() {
            return Ok(JpegPhoto::null());
        }
        // Confirm that it's a valid Jpeg, then store only the bytes.
        image::io::Reader::with_format(std::io::Cursor::new(bytes), image::ImageFormat::Jpeg)
            .decode()?;
        Ok(JpegPhoto(bytes.to_vec()))
    }
}

impl TryFrom<Vec<u8>> for JpegPhoto {
    type Error = anyhow::Error;
    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        if bytes.is_empty() {
            return Ok(JpegPhoto::null());
        }
        // Confirm that it's a valid Jpeg, then store only the bytes.
        image::io::Reader::with_format(
            std::io::Cursor::new(bytes.as_slice()),
            image::ImageFormat::Jpeg,
        )
        .decode()?;
        Ok(JpegPhoto(bytes))
    }
}

impl TryFrom<&str> for JpegPhoto {
    type Error = anyhow::Error;
    fn try_from(string: &str) -> anyhow::Result<Self> {
        // The String format is in base64.
        <Self as TryFrom<_>>::try_from(base64::engine::general_purpose::STANDARD.decode(string)?)
    }
}

impl From<&JpegPhoto> for String {
    fn from(val: &JpegPhoto) -> Self {
        base64::engine::general_purpose::STANDARD.encode(&val.0)
    }
}

impl std::fmt::Debug for JpegPhoto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(&self.0);
        if encoded.len() > 100 {
            encoded.truncate(100);
            encoded.push_str(" ...");
        };
        f.debug_tuple("JpegPhoto")
            .field(&format!("b64[{}]", encoded))
            .finish()
    }
}

impl JpegPhoto {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn null() -> Self {
        Self(vec![])
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[cfg(any(feature = "test", test))]
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

impl Nullable for JpegPhoto {
    fn null() -> Value {
        JpegPhoto::null().into()
    }
}

impl IntoActiveValue<Serialized> for JpegPhoto {
    fn into_active_value(self) -> sea_orm::ActiveValue<Serialized> {
        if self.is_empty() {
            sea_orm::ActiveValue::NotSet
        } else {
            sea_orm::ActiveValue::Set(Serialized::from(&self))
        }
    }
}

// Represents values that can be either a singleton or a list of a specific type
// Used by AttributeValue to model attributes with types that might be a list.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Hash)]
pub enum Cardinality<T: Clone> {
    Singleton(T),
    Unbounded(Vec<T>),
}

impl<T: Clone> Cardinality<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::Singleton(v) => vec![v],
            Self::Unbounded(l) => l,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Hash)]
pub enum AttributeValue {
    String(Cardinality<String>),
    Integer(Cardinality<i64>),
    JpegPhoto(Cardinality<JpegPhoto>),
    DateTime(Cardinality<NaiveDateTime>),
}

impl AttributeValue {
    pub fn get_attribute_type(&self) -> AttributeType {
        match self {
            Self::String(_) => AttributeType::String,
            Self::Integer(_) => AttributeType::Integer,
            Self::JpegPhoto(_) => AttributeType::JpegPhoto,
            Self::DateTime(_) => AttributeType::DateTime,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let AttributeValue::String(Cardinality::Singleton(s)) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
    pub fn into_string(self) -> Option<String> {
        if let AttributeValue::String(Cardinality::Singleton(s)) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_jpeg_photo(&self) -> Option<&JpegPhoto> {
        if let AttributeValue::JpegPhoto(Cardinality::Singleton(p)) = self {
            Some(p)
        } else {
            None
        }
    }
}

impl From<String> for AttributeValue {
    fn from(s: String) -> Self {
        AttributeValue::String(Cardinality::Singleton(s))
    }
}
impl From<Vec<String>> for AttributeValue {
    fn from(l: Vec<String>) -> Self {
        AttributeValue::String(Cardinality::Unbounded(l))
    }
}

impl From<i64> for AttributeValue {
    fn from(i: i64) -> Self {
        AttributeValue::Integer(Cardinality::Singleton(i))
    }
}
impl From<Vec<i64>> for AttributeValue {
    fn from(l: Vec<i64>) -> Self {
        AttributeValue::Integer(Cardinality::Unbounded(l))
    }
}

impl From<JpegPhoto> for AttributeValue {
    fn from(j: JpegPhoto) -> Self {
        AttributeValue::JpegPhoto(Cardinality::Singleton(j))
    }
}
impl From<Vec<JpegPhoto>> for AttributeValue {
    fn from(l: Vec<JpegPhoto>) -> Self {
        AttributeValue::JpegPhoto(Cardinality::Unbounded(l))
    }
}

impl From<NaiveDateTime> for AttributeValue {
    fn from(dt: NaiveDateTime) -> Self {
        AttributeValue::DateTime(Cardinality::Singleton(dt))
    }
}
impl From<Vec<NaiveDateTime>> for AttributeValue {
    fn from(l: Vec<NaiveDateTime>) -> Self {
        AttributeValue::DateTime(Cardinality::Unbounded(l))
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Hash)]
pub struct Attribute {
    pub name: AttributeName,
    pub value: AttributeValue,
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: UserId,
    pub email: Email,
    pub display_name: Option<String>,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub attributes: Vec<Attribute>,
}

#[cfg(feature = "test")]
impl Default for User {
    fn default() -> Self {
        let epoch = chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc();
        User {
            user_id: UserId::default(),
            email: Email::default(),
            display_name: None,
            creation_date: epoch,
            uuid: Uuid::from_name_and_date("", &epoch),
            attributes: Vec::new(),
        }
    }
}

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    DeriveValueType,
    derive_more::Debug,
)]
#[debug("{_0}")]
pub struct GroupId(pub i32);

impl TryFromU64 for GroupId {
    fn try_from_u64(n: u64) -> Result<Self, DbErr> {
        Ok(GroupId(i32::try_from_u64(n)?))
    }
}

impl From<&GroupId> for Value {
    fn from(id: &GroupId) -> Self {
        (*id).into()
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumString,
    IntoStaticStr,
    juniper::GraphQLEnum,
)]
pub enum AttributeType {
    String,
    Integer,
    JpegPhoto,
    DateTime,
}

impl From<AttributeType> for Value {
    fn from(attribute_type: AttributeType) -> Self {
        Into::<&'static str>::into(attribute_type).into()
    }
}

impl TryGetable for AttributeType {
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        use std::str::FromStr;
        Ok(AttributeType::from_str(&String::try_get_by(res, index)?).expect("Invalid enum value"))
    }
}

impl ValueType for AttributeType {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        use std::str::FromStr;
        Ok(
            AttributeType::from_str(&<String as ValueType>::try_from(v)?)
                .expect("Invalid enum value"),
        )
    }

    fn type_name() -> String {
        "AttributeType".to_owned()
    }

    fn array_type() -> ArrayType {
        ArrayType::String
    }

    fn column_type() -> ColumnType {
        ColumnType::String(Some(64))
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub display_name: GroupName,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub users: Vec<UserId>,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupDetails {
    pub group_id: GroupId,
    pub display_name: GroupName,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAndGroups {
    pub user: User,
    pub groups: Option<Vec<GroupDetails>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_serialized_debug_string() {
        assert_eq!(
            &format!("{:?}", Serialized::from("abcd")),
            "Serialized(\"abcd\")"
        );
        assert_eq!(
            &format!("{:?}", Serialized::from(&1234i64)),
            "Serialized(\"1234\")"
        );
        assert_eq!(
            &format!("{:?}", Serialized::from(&JpegPhoto::for_tests())),
            "Serialized(\"hash: 0xB947C77A16F3C3BD\")"
        );
    }

    #[test]
    fn test_serialized_i64_len() {
        assert_eq!(SERIALIZED_I64_LEN, Serialized::from(&0i64).0.len());
        assert_eq!(SERIALIZED_I64_LEN, Serialized::from(&i64::MAX).0.len());
        assert_eq!(SERIALIZED_I64_LEN, Serialized::from(&i64::MIN).0.len());
        assert_eq!(SERIALIZED_I64_LEN, Serialized::from(&-1000i64).0.len());
    }
}
