use base64::Engine;
use chrono::{NaiveDateTime, TimeZone};
use sea_orm::{
    entity::IntoActiveValue,
    sea_query::{value::ValueType, ArrayType, BlobSize, ColumnType, Nullable, ValueTypeErr},
    strum::{EnumString, IntoStaticStr},
    DbErr, FromQueryResult, QueryResult, TryFromU64, TryGetError, TryGetable, Value,
};
use serde::{Deserialize, Serialize};

pub use super::model::{GroupColumn, UserColumn};

#[derive(PartialEq, Hash, Eq, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(try_from = "&str")]
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

impl std::string::ToString for Uuid {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl TryGetable for Uuid {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        index: I,
    ) -> std::result::Result<Self, TryGetError> {
        Ok(Uuid(String::try_get_by(res, index)?))
    }
}

impl ValueType for Uuid {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        <Self as std::convert::TryFrom<_>>::try_from(
            <std::string::String as sea_orm::sea_query::ValueType>::try_from(v)?.as_str(),
        )
        .map_err(|_| ValueTypeErr {})
    }

    fn type_name() -> String {
        "Uuid".to_owned()
    }

    fn array_type() -> ArrayType {
        ArrayType::String
    }

    fn column_type() -> ColumnType {
        ColumnType::String(Some(36))
    }
}

impl From<Uuid> for Value {
    fn from(uuid: Uuid) -> Self {
        uuid.as_str().into()
    }
}

impl From<&Uuid> for Value {
    fn from(uuid: &Uuid) -> Self {
        uuid.as_str().into()
    }
}

#[cfg(test)]
#[macro_export]
macro_rules! uuid {
    ($s:literal) => {
        <$crate::domain::types::Uuid as std::convert::TryFrom<_>>::try_from($s).unwrap()
    };
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    fn convert_to<'a, T: Deserialize<'a>>(&'a self) -> bincode::Result<T> {
        bincode::deserialize(&self.0)
    }

    pub fn unwrap<'a, T: Deserialize<'a>>(&'a self) -> T {
        self.convert_to().unwrap()
    }

    pub fn expect<'a, T: Deserialize<'a>>(&'a self, message: &str) -> T {
        self.convert_to().expect(message)
    }
}

impl From<Serialized> for Value {
    fn from(ser: Serialized) -> Self {
        ser.0.into()
    }
}

impl TryGetable for Serialized {
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        Ok(Self(Vec::<u8>::try_get_by(res, index)?))
    }
}

impl TryFromU64 for Serialized {
    fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(
            "Serialized cannot be constructed from u64",
        ))
    }
}

impl ValueType for Serialized {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        Ok(Self(<Vec<u8> as ValueType>::try_from(v)?))
    }

    fn type_name() -> String {
        "Serialized".to_owned()
    }

    fn array_type() -> ArrayType {
        ArrayType::Bytes
    }

    fn column_type() -> ColumnType {
        ColumnType::Binary(BlobSize::Long)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(from = "String")]
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

impl From<UserId> for Value {
    fn from(user_id: UserId) -> Self {
        user_id.into_string().into()
    }
}

impl From<&UserId> for Value {
    fn from(user_id: &UserId) -> Self {
        user_id.as_str().into()
    }
}

impl TryGetable for UserId {
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        Ok(UserId::new(&String::try_get_by(res, index)?))
    }
}

impl TryFromU64 for UserId {
    fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(
            "UserId cannot be constructed from u64",
        ))
    }
}

impl ValueType for UserId {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        Ok(UserId::new(<String as ValueType>::try_from(v)?.as_str()))
    }

    fn type_name() -> String {
        "UserId".to_owned()
    }

    fn array_type() -> ArrayType {
        ArrayType::String
    }

    fn column_type() -> ColumnType {
        ColumnType::String(Some(255))
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct JpegPhoto(#[serde(with = "serde_bytes")] Vec<u8>);

impl From<JpegPhoto> for Value {
    fn from(photo: JpegPhoto) -> Self {
        photo.0.into()
    }
}

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

impl TryFrom<String> for JpegPhoto {
    type Error = anyhow::Error;
    fn try_from(string: String) -> anyhow::Result<Self> {
        // The String format is in base64.
        <Self as TryFrom<_>>::try_from(
            base64::engine::general_purpose::STANDARD.decode(string.as_str())?,
        )
    }
}

impl From<&JpegPhoto> for String {
    fn from(val: &JpegPhoto) -> Self {
        base64::engine::general_purpose::STANDARD.encode(&val.0)
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

impl TryGetable for JpegPhoto {
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        <Self as std::convert::TryFrom<Vec<_>>>::try_from(Vec::<u8>::try_get_by(res, index)?)
            .map_err(|e| {
                TryGetError::DbErr(DbErr::TryIntoErr {
                    from: "[u8]",
                    into: "JpegPhoto",
                    source: e.into(),
                })
            })
    }
}

impl ValueType for JpegPhoto {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        <Self as std::convert::TryFrom<_>>::try_from(
            <Vec<u8> as sea_orm::sea_query::ValueType>::try_from(v)?.as_slice(),
        )
        .map_err(|_| ValueTypeErr {})
    }

    fn type_name() -> String {
        "JpegPhoto".to_owned()
    }

    fn array_type() -> ArrayType {
        ArrayType::Bytes
    }

    fn column_type() -> ColumnType {
        ColumnType::Binary(BlobSize::Long)
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

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct AttributeValue {
    pub name: String,
    pub value: Serialized,
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub attributes: Vec<AttributeValue>,
}

#[cfg(test)]
impl Default for User {
    fn default() -> Self {
        let epoch = chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc();
        User {
            user_id: UserId::default(),
            email: String::new(),
            display_name: None,
            creation_date: epoch,
            uuid: Uuid::from_name_and_date("", &epoch),
            attributes: Vec::new(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub i32);

impl From<GroupId> for Value {
    fn from(group_id: GroupId) -> Self {
        group_id.0.into()
    }
}

impl TryGetable for GroupId {
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        Ok(GroupId(i32::try_get_by(res, index)?))
    }
}

impl ValueType for GroupId {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        Ok(GroupId(<i32 as ValueType>::try_from(v)?))
    }

    fn type_name() -> String {
        "GroupId".to_owned()
    }

    fn array_type() -> ArrayType {
        ArrayType::Int
    }

    fn column_type() -> ColumnType {
        ColumnType::Integer
    }
}

impl TryFromU64 for GroupId {
    fn try_from_u64(n: u64) -> Result<Self, DbErr> {
        Ok(GroupId(i32::try_from_u64(n)?))
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString, IntoStaticStr,
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

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub display_name: String,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub users: Vec<UserId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, FromQueryResult)]
pub struct GroupDetails {
    pub group_id: GroupId,
    pub display_name: String,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAndGroups {
    pub user: User,
    pub groups: Option<Vec<GroupDetails>>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            SERIALIZED_I64_LEN,
            Serialized::from(&i64::max_value()).0.len()
        );
        assert_eq!(
            SERIALIZED_I64_LEN,
            Serialized::from(&i64::min_value()).0.len()
        );
        assert_eq!(SERIALIZED_I64_LEN, Serialized::from(&-1000i64).0.len());
    }
}
