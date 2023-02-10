use chrono::{NaiveDateTime, TimeZone};
use sea_orm::{
    entity::IntoActiveValue,
    sea_query::{value::ValueType, ArrayType, ColumnType, Nullable, ValueTypeErr},
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

#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize, Deserialize)]
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
        <Self as TryFrom<_>>::try_from(base64::decode(string.as_str())?)
    }
}

impl From<&JpegPhoto> for String {
    fn from(val: &JpegPhoto) -> Self {
        base64::encode(&val.0)
    }
}

impl JpegPhoto {
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
        ColumnType::Binary(sea_orm::sea_query::BlobSize::Long)
    }
}

impl Nullable for JpegPhoto {
    fn null() -> Value {
        JpegPhoto::null().into()
    }
}

impl IntoActiveValue<JpegPhoto> for JpegPhoto {
    fn into_active_value(self) -> sea_orm::ActiveValue<JpegPhoto> {
        sea_orm::ActiveValue::Set(self)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, FromQueryResult)]
pub struct User {
    pub user_id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<JpegPhoto>,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
}

#[cfg(test)]
impl Default for User {
    fn default() -> Self {
        let epoch = chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc();
        User {
            user_id: UserId::default(),
            email: String::new(),
            display_name: None,
            first_name: None,
            last_name: None,
            avatar: None,
            creation_date: epoch,
            uuid: Uuid::from_name_and_date("", &epoch),
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
