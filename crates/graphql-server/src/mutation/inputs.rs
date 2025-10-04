use juniper::{GraphQLInputObject, GraphQLObject};

#[derive(Clone, PartialEq, Eq, Debug, GraphQLInputObject)]
// This conflicts with the attribute values returned by the user/group queries.
#[graphql(name = "AttributeValueInput")]
pub struct AttributeValue {
    /// The name of the attribute. It must be present in the schema, and the type informs how
    /// to interpret the values.
    pub name: String,
    /// The values of the attribute.
    /// If the attribute is not a list, the vector must contain exactly one element.
    /// Integers (signed 64 bits) are represented as strings.
    /// Dates are represented as strings in RFC3339 format, e.g. "2019-10-12T07:20:50.52Z".
    /// JpegPhotos are represented as base64 encoded strings. They must be valid JPEGs.
    pub value: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The details required to create a user.
pub struct CreateUserInput {
    pub id: String,
    // The email can be specified as an attribute, but one of the two is required.
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// First name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    pub first_name: Option<String>,
    /// Last name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    pub last_name: Option<String>,
    /// Base64 encoded JpegPhoto. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    pub avatar: Option<String>,
    /// Attributes.
    pub attributes: Option<Vec<AttributeValue>>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The details required to create a group.
pub struct CreateGroupInput {
    pub display_name: String,
    /// User-defined attributes.
    pub attributes: Option<Vec<AttributeValue>>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The fields that can be updated for a user.
pub struct UpdateUserInput {
    pub id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// First name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    pub first_name: Option<String>,
    /// Last name of user. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    pub last_name: Option<String>,
    /// Base64 encoded JpegPhoto. Deprecated: use attribute instead.
    /// If both field and corresponding attribute is supplied, the attribute will take precedence.
    pub avatar: Option<String>,
    /// Attribute names to remove.
    /// They are processed before insertions.
    pub remove_attributes: Option<Vec<String>>,
    /// Inserts or updates the given attributes.
    /// For lists, the entire list must be provided.
    pub insert_attributes: Option<Vec<AttributeValue>>,
}

#[derive(PartialEq, Eq, Debug, GraphQLInputObject)]
/// The fields that can be updated for a group.
pub struct UpdateGroupInput {
    /// The group ID.
    pub id: i32,
    /// The new display name.
    pub display_name: Option<String>,
    /// Attribute names to remove.
    /// They are processed before insertions.
    pub remove_attributes: Option<Vec<String>>,
    /// Inserts or updates the given attributes.
    /// For lists, the entire list must be provided.
    pub insert_attributes: Option<Vec<AttributeValue>>,
}

#[derive(PartialEq, Eq, Debug, GraphQLObject)]
pub struct Success {
    ok: bool,
}

impl Success {
    pub fn new() -> Self {
        Self { ok: true }
    }
}

impl Default for Success {
    fn default() -> Self {
        Self::new()
    }
}
