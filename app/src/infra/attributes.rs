pub struct AttributeDescription<'a> {
    pub attribute_identifier: &'a str,
    pub attribute_name: &'a str,
    pub aliases: Vec<&'a str>,
}

pub mod group {

    use super::AttributeDescription;

    pub fn resolve_group_attribute_description(name: &str) -> Option<AttributeDescription> {
        match name {
            "creation_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "creationdate",
                aliases: vec![name, "createtimestamp"],
            }),
            "modified_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "modifydate",
                aliases: vec![name, "modifytimestamp"],
            }),
            "display_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "displayname",
                aliases: vec![name, "cn", "uid", "id"],
            }),
            "group_id" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "groupid",
                aliases: vec![name],
            }),
            "uuid" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["entryuuid"],
            }),
            _ => None,
        }
    }

    pub fn resolve_group_attribute_description_or_default(name: &str) -> AttributeDescription {
        match resolve_group_attribute_description(name) {
            Some(d) => d,
            None => AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec![],
            },
        }
    }
}

pub mod user {

    use super::AttributeDescription;

    pub fn resolve_user_attribute_description(name: &str) -> Option<AttributeDescription> {
        match name {
            "avatar" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["jpegphoto"],
            }),
            "creation_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "creationdate",
                aliases: vec![name, "createtimestamp"],
            }),
            "modified_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "modifydate",
                aliases: vec![name, "modifytimestamp"],
            }),
            "password_modified_date" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "passwordmodifydate",
                aliases: vec![name, "pwdchangedtime"],
            }),
            "display_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "displayname",
                aliases: vec![name, "cn"],
            }),
            "first_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "firstname",
                aliases: vec![name, "givenname"],
            }),
            "last_name" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "lastname",
                aliases: vec![name, "sn"],
            }),
            "mail" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["email"],
            }),
            "user_id" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: "uid",
                aliases: vec![name, "id"],
            }),
            "uuid" => Some(AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec!["entryuuid"],
            }),
            _ => None,
        }
    }

    pub fn resolve_user_attribute_description_or_default(name: &str) -> AttributeDescription {
        match resolve_user_attribute_description(name) {
            Some(d) => d,
            None => AttributeDescription {
                attribute_identifier: name,
                attribute_name: name,
                aliases: vec![],
            },
        }
    }
}
