use crate::{
    domain::{
        deserialize,
        ldap::{
            error::{LdapError, LdapResult},
            group::{convert_groups_to_ldap_op, get_default_group_object_classes, get_groups_list},
            user::{convert_users_to_ldap_op, get_default_user_object_classes, get_user_list},
            utils::{
                get_user_id_from_distinguished_name, is_subtree, parse_distinguished_name, LdapInfo,
            },
        },
        opaque_handler::OpaqueHandler,
        schema::PublicSchema,
    },
    infra::access_control::{
        AccessControlledBackendHandler, AdminBackendHandler, UserAndGroupListerBackendHandler,
        UserReadableBackendHandler, ValidationResults,
    },
};
use anyhow::Result;
use chrono::Utc;
use itertools::Itertools;
use ldap3_proto::proto::{
    LdapAddRequest, LdapBindCred, LdapBindRequest, LdapBindResponse, LdapCompareRequest,
    LdapDerefAliases, LdapExtendedRequest, LdapExtendedResponse, LdapFilter, LdapModify,
    LdapModifyRequest, LdapModifyType, LdapOp, LdapPartialAttribute, LdapPasswordModifyRequest,
    LdapResult as LdapResultOp, LdapResultCode, LdapSearchRequest, LdapSearchResultEntry,
    LdapSearchScope, OID_PASSWORD_MODIFY, OID_WHOAMI,
};
use lldap_domain::{
    schema::{Schema, AttributeSchema, AttributeList},
    requests::CreateUserRequest,
    types::{Attribute, AttributeName, AttributeType, Email, Group, LdapObjectClass, UserAndGroups, UserId},
};
use lldap_domain_handlers::handler::{
    BackendHandler, BindRequest, LoginHandler, ReadSchemaBackendHandler,
};

use std::collections::HashMap;
use tracing::{debug, instrument, warn};

#[derive(Debug)]
enum SearchScope {
    Global,
    Users,
    Groups,
    User(LdapFilter),
    Group(LdapFilter),
    UserOuOnly,
    GroupOuOnly,
    Unknown,
    Invalid,
}

enum InternalSearchResults {
    UsersAndGroups(Vec<UserAndGroups>, Vec<Group>),
    Raw(Vec<LdapOp>),
    Empty,
}

fn get_search_scope(
    base_dn: &[(String, String)],
    dn_parts: &[(String, String)],
    ldap_scope: &LdapSearchScope,
) -> SearchScope {
    let base_dn_len = base_dn.len();
    if !is_subtree(dn_parts, base_dn) {
        SearchScope::Invalid
    } else if dn_parts.len() == base_dn_len {
        SearchScope::Global
    } else if dn_parts.len() == base_dn_len + 1
        && dn_parts[0] == ("ou".to_string(), "people".to_string())
    {
        if matches!(ldap_scope, LdapSearchScope::Base) {
            SearchScope::UserOuOnly
        } else {
            SearchScope::Users
        }
    } else if dn_parts.len() == base_dn_len + 1
        && dn_parts[0] == ("ou".to_string(), "groups".to_string())
    {
        if matches!(ldap_scope, LdapSearchScope::Base) {
            SearchScope::GroupOuOnly
        } else {
            SearchScope::Groups
        }
    } else if dn_parts.len() == base_dn_len + 2
        && dn_parts[1] == ("ou".to_string(), "people".to_string())
    {
        SearchScope::User(LdapFilter::Equality(
            dn_parts[0].0.clone(),
            dn_parts[0].1.clone(),
        ))
    } else if dn_parts.len() == base_dn_len + 2
        && dn_parts[1] == ("ou".to_string(), "groups".to_string())
    {
        SearchScope::Group(LdapFilter::Equality(
            dn_parts[0].0.clone(),
            dn_parts[0].1.clone(),
        ))
    } else {
        SearchScope::Unknown
    }
}

fn make_search_request<S: Into<String>>(
    base: &str,
    filter: LdapFilter,
    attrs: Vec<S>,
) -> LdapSearchRequest {
    LdapSearchRequest {
        base: base.to_string(),
        scope: LdapSearchScope::Subtree,
        aliases: LdapDerefAliases::Never,
        sizelimit: 0,
        timelimit: 0,
        typesonly: false,
        filter,
        attrs: attrs.into_iter().map(Into::into).collect(),
    }
}

fn make_search_success() -> LdapOp {
    make_search_error(LdapResultCode::Success, "".to_string())
}

fn make_search_error(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::SearchResultDone(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

fn make_add_error(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::AddResponse(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

fn make_extended_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::ExtendedResponse(LdapExtendedResponse {
        res: LdapResultOp {
            code,
            matcheddn: "".to_string(),
            message,
            referral: vec![],
        },
        name: None,
        value: None,
    })
}

fn make_modify_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::ModifyResponse(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

fn root_dse_response(base_dn: &str) -> LdapOp {
    LdapOp::SearchResultEntry(LdapSearchResultEntry {
        dn: "".to_string(),
        attributes: vec![
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorName".to_string(),
                vals: vec![b"LLDAP".to_vec()],
            },
            LdapPartialAttribute {
                atype: "vendorVersion".to_string(),
                vals: vec![concat!("lldap_", env!("CARGO_PKG_VERSION"))
                    .to_string()
                    .into_bytes()],
            },
            LdapPartialAttribute {
                atype: "supportedLDAPVersion".to_string(),
                vals: vec![b"3".to_vec()],
            },
            LdapPartialAttribute {
                atype: "supportedExtension".to_string(),
                vals: vec![
                    OID_PASSWORD_MODIFY.as_bytes().to_vec(),
                    OID_WHOAMI.as_bytes().to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "supportedControl".to_string(),
                vals: vec![],
            },
            LdapPartialAttribute {
                atype: "supportedFeatures".to_string(),
                // Attribute "+"
                vals: vec![b"1.3.6.1.4.1.4203.1.5.1".to_vec()],
            },
            LdapPartialAttribute {
                atype: "defaultNamingContext".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "namingContexts".to_string(),
                vals: vec![base_dn.to_string().into_bytes()],
            },
            LdapPartialAttribute {
                atype: "isGlobalCatalogReady".to_string(),
                vals: vec![b"false".to_vec()],
            },
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![b"cn=Subschema".to_vec()],
            },
        ],
    })
}

pub struct ObjectClassList(Vec<LdapObjectClass>);

// See RFC4512 section 4.2.1 "objectClasses"
impl ObjectClassList {
    fn format_for_ldap_schema_description(&self) -> String {
        self.0
            .iter()
            .map(|c| format!("'{}'", c))
            .unique()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// See RFC4512 section 4.2 "Subschema Subentries"
// This struct holds all information on what attributes and objectclasses are present on the server.
// It can be used to 'index' a server using a LDAP subschema call.
pub struct LdapSchemaDescription {
    user_attributes_must: AttributeList,
    user_attributes_may: AttributeList,
    group_attributes_must: AttributeList,
    group_attributes_may: AttributeList,
    user_object_classes: ObjectClassList,
    group_object_classes: ObjectClassList,
}

impl LdapSchemaDescription {
    fn extend_with_custom_schema(mut self, schema: &Schema) -> Self {
        self.user_attributes_may
            .attributes
            .extend(schema.user_attributes.attributes.clone());
        self.group_attributes_may
            .attributes
            .extend(schema.group_attributes.attributes.clone());
        self.user_object_classes
            .0
            .extend(schema.extra_user_object_classes.clone());
        self.group_object_classes
            .0
            .extend(schema.extra_group_object_classes.clone());

        self
    }

    // See RFC4512 section 4.2.2 "attributeTypes"
    fn formatted_attribute_list(&self) -> Vec<Vec<u8>> {
        let mut formatted_list: Vec<Vec<u8>> = Vec::new();

        for (index, attribute) in self.all_attributes().attributes.into_iter().enumerate() {
            formatted_list.push(
                format!(
                    "( 2.{} NAME '{}' DESC 'LLDAP: {}' SUP {:?} )",
                    (index + 4),
                    attribute.name,
                    if attribute.is_hardcoded {
                        "builtin attribute"
                    } else {
                        "custom attribute"
                    },
                    attribute.attribute_type
                )
                .into_bytes()
                .to_vec(),
            )
        }

        formatted_list
    }

    pub fn all_attributes(&self) -> AttributeList {
        AttributeList {
            attributes: [
                self.user_attributes_must.attributes.clone(),
                self.user_attributes_may.attributes.clone(),
                self.group_attributes_must.attributes.clone(),
                self.group_attributes_may.attributes.clone(),
            ]
            .concat()
            .iter()
            .unique_by(|a| &a.name)
            .cloned()
            .collect::<Vec<_>>(),
        }
    }
}

fn get_lldap_builtin_schema() -> LdapSchemaDescription {
    LdapSchemaDescription {
        user_attributes_must: AttributeList {
            attributes: vec![
                AttributeSchema {
                    name: "uid".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "mail".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
            ],
        },
        user_attributes_may: AttributeList {
            attributes: vec![
                AttributeSchema {
                    name: "objectclass".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "givenname".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "sn".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "cn".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "jpegPhoto".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "createtimestamp".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "entryuuid".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
            ],
        },
        group_attributes_must: AttributeList {
            attributes: vec![
                AttributeSchema {
                    name: "uid".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "cn".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
            ],
        },
        group_attributes_may: AttributeList {
            attributes: vec![
                AttributeSchema {
                    name: "objectclass".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "member".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "uniquemember".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
                AttributeSchema {
                    name: "entryuuid".into(),
                    attribute_type: AttributeType::String,
                    is_list: false,
                    is_visible: true,
                    is_editable: false,
                    is_hardcoded: true,
                    is_readonly: true,
                },
            ],
        },
        user_object_classes: ObjectClassList(get_default_user_object_classes()),
        group_object_classes: ObjectClassList(get_default_group_object_classes()),
    }
}

fn schema_response(schema: &Schema) -> LdapOp {
    let full_schema: LdapSchemaDescription =
        get_lldap_builtin_schema().extend_with_custom_schema(schema);

    let current_time_utc = Utc::now().format("%Y%m%d%H%M%SZ").to_string().into_bytes();

    LdapOp::SearchResultEntry(LdapSearchResultEntry {
        dn: "cn=Subschema".to_string(),
        attributes: vec![
           LdapPartialAttribute {
            atype: "structuralObjectClass".to_string(),
            vals: vec![b"subentry".to_vec()],
           },
           LdapPartialAttribute {
            atype: "objectClass".to_string(),
            vals: vec![b"top".to_vec(), b"subentry".to_vec(), b"subschema".to_vec(), b"extensibleObject".to_vec()],
           },
           LdapPartialAttribute {
            atype: "cn".to_string(),
            vals: vec![b"Subschema".to_vec()],
           },
           LdapPartialAttribute {
            atype: "createTimestamp".to_string(),
            vals: vec![current_time_utc.to_vec()],
           },
           LdapPartialAttribute {
            atype: "modifyTimestamp".to_string(),
            vals: vec![current_time_utc.to_vec()],
           },
           LdapPartialAttribute {
            atype: "ldapSyntaxes".to_string(),
            vals: vec![
                b"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )".to_vec(),
                b"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )".to_vec(),
                b"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )".to_vec(),
                b"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' X-NOT-HUMAN-READABLE 'TRUE' )".to_vec(),
                ],
           },
           LdapPartialAttribute {
            atype: "attributeTypes".to_string(),
            vals: vec![
                b"( 2.0 NAME 'String' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".to_vec(),
                b"( 2.1 NAME 'Integer' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )".to_vec(),
                b"( 2.2 NAME 'JpegPhoto' SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )".to_vec(),
                b"( 2.3 NAME 'DateTime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".to_vec(),
                ].into_iter().chain(
                    full_schema.formatted_attribute_list()
                ).collect()
           },
           LdapPartialAttribute {
            atype: "objectClasses".to_string(),
            vals: vec![
                    format!(
                        "( 3.0 NAME ( {} ) DESC 'LLDAP builtin: a person' STRUCTURAL MUST ( {} ) MAY ( {} ) )",
                        full_schema.user_object_classes.format_for_ldap_schema_description(),
                        full_schema.user_attributes_must.format_for_ldap_schema_description(),
                        full_schema.user_attributes_may.format_for_ldap_schema_description(),
                    ).into_bytes(),
                    format!(
                        "( 3.1 NAME ( {} ) DESC 'LLDAP builtin: a group' STRUCTURAL MUST ( {} ) MAY ( {} ) )",
                        full_schema.group_object_classes.format_for_ldap_schema_description(),
                        full_schema.group_attributes_must.format_for_ldap_schema_description(),
                        full_schema.group_attributes_may.format_for_ldap_schema_description(),
                    ).into_bytes(),
                ],
           },
           LdapPartialAttribute {
            atype: "subschemaSubentry".to_string(),
            vals: vec![b"cn=Subschema".to_vec()],
           },
        ],
    })
}

pub struct LdapHandler<Backend> {
    user_info: Option<ValidationResults>,
    backend_handler: AccessControlledBackendHandler<Backend>,
    ldap_info: LdapInfo,
    session_uuid: uuid::Uuid,
}

impl<Backend> LdapHandler<Backend> {
    pub fn session_uuid(&self) -> &uuid::Uuid {
        &self.session_uuid
    }
}

impl<Backend: LoginHandler> LdapHandler<Backend> {
    pub fn get_login_handler(&self) -> &impl LoginHandler {
        self.backend_handler.unsafe_get_handler()
    }
}

impl<Backend: OpaqueHandler> LdapHandler<Backend> {
    pub fn get_opaque_handler(&self) -> &impl OpaqueHandler {
        self.backend_handler.unsafe_get_handler()
    }
}

impl<Backend: BackendHandler + LoginHandler + OpaqueHandler> LdapHandler<Backend> {
    pub fn new(
        backend_handler: AccessControlledBackendHandler<Backend>,
        mut ldap_base_dn: String,
        ignored_user_attributes: Vec<AttributeName>,
        ignored_group_attributes: Vec<AttributeName>,
        session_uuid: uuid::Uuid,
    ) -> Self {
        ldap_base_dn.make_ascii_lowercase();
        Self {
            user_info: None,
            backend_handler,
            ldap_info: LdapInfo {
                base_dn: parse_distinguished_name(&ldap_base_dn).unwrap_or_else(|_| {
                    panic!(
                        "Invalid value for ldap_base_dn in configuration: {}",
                        ldap_base_dn
                    )
                }),
                base_dn_str: ldap_base_dn,
                ignored_user_attributes,
                ignored_group_attributes,
            },
            session_uuid,
        }
    }

    #[cfg(test)]
    pub fn new_for_tests(backend_handler: Backend, ldap_base_dn: &str) -> Self {
        Self::new(
            AccessControlledBackendHandler::new(backend_handler),
            ldap_base_dn.to_string(),
            vec![],
            vec![],
            uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        )
    }

    #[instrument(skip_all, level = "debug", fields(dn = %request.dn))]
    pub async fn do_bind(&mut self, request: &LdapBindRequest) -> (LdapResultCode, String) {
        if request.dn.is_empty() {
            return (
                LdapResultCode::InappropriateAuthentication,
                "Anonymous bind not allowed".to_string(),
            );
        }
        let user_id = match get_user_id_from_distinguished_name(
            &request.dn.to_ascii_lowercase(),
            &self.ldap_info.base_dn,
            &self.ldap_info.base_dn_str,
        ) {
            Ok(s) => s,
            Err(e) => return (LdapResultCode::NamingViolation, e.to_string()),
        };
        let password = if let LdapBindCred::Simple(password) = &request.cred {
            password
        } else {
            return (
                LdapResultCode::UnwillingToPerform,
                "SASL not supported".to_string(),
            );
        };
        match self
            .get_login_handler()
            .bind(BindRequest {
                name: user_id.clone(),
                password: password.clone(),
            })
            .await
        {
            Ok(()) => {
                self.user_info = self
                    .backend_handler
                    .get_permissions_for_user(user_id)
                    .await
                    .ok();
                debug!("Success!");
                (LdapResultCode::Success, "".to_string())
            }
            Err(_) => (LdapResultCode::InvalidCredentials, "".to_string()),
        }
    }

    async fn change_password<B: OpaqueHandler>(
        &self,
        backend_handler: &B,
        user: UserId,
        password: &[u8],
    ) -> Result<()> {
        use lldap_auth::*;
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration(password, &mut rng)?;
        let req = registration::ClientRegistrationStartRequest {
            username: user.clone(),
            registration_start_request: registration_start_request.message,
        };
        let registration_start_response = backend_handler.registration_start(req).await?;
        let registration_finish = opaque::client::registration::finish_registration(
            registration_start_request.state,
            registration_start_response.registration_response,
            &mut rng,
        )?;
        let req = registration::ClientRegistrationFinishRequest {
            server_data: registration_start_response.server_data,
            registration_upload: registration_finish.message,
        };
        backend_handler.registration_finish(req).await?;
        Ok(())
    }

    async fn do_password_modification(
        &mut self,
        request: &LdapPasswordModifyRequest,
    ) -> LdapResult<Vec<LdapOp>> {
        let credentials = self.user_info.as_ref().ok_or_else(|| LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: "No user currently bound".to_string(),
        })?;
        match (&request.user_identity, &request.new_password) {
            (Some(user), Some(password)) => {
                match get_user_id_from_distinguished_name(
                    &user.to_ascii_lowercase(),
                    &self.ldap_info.base_dn,
                    &self.ldap_info.base_dn_str,
                ) {
                    Ok(uid) => {
                        let user_is_admin = self
                            .backend_handler
                            .get_readable_handler(credentials, &uid)
                            .expect("Unexpected permission error")
                            .get_user_groups(&uid)
                            .await
                            .map_err(|e| LdapError {
                                code: LdapResultCode::OperationsError,
                                message: format!(
                                    "Internal error while requesting user's groups: {:#?}",
                                    e
                                ),
                            })?
                            .iter()
                            .any(|g| g.display_name == "lldap_admin".into());
                        if !credentials.can_change_password(&uid, user_is_admin) {
                            Err(LdapError {
                                code: LdapResultCode::InsufficentAccessRights,
                                message: format!(
                                    r#"User `{}` cannot modify the password of user `{}`"#,
                                    &credentials.user, &uid
                                ),
                            })
                        } else if let Err(e) = self
                            .change_password(self.get_opaque_handler(), uid, password.as_bytes())
                            .await
                        {
                            Err(LdapError {
                                code: LdapResultCode::Other,
                                message: format!("Error while changing the password: {:#?}", e),
                            })
                        } else {
                            Ok(vec![make_extended_response(
                                LdapResultCode::Success,
                                "".to_string(),
                            )])
                        }
                    }
                    Err(e) => Err(LdapError {
                        code: LdapResultCode::InvalidDNSyntax,
                        message: format!("Invalid username: {}", e),
                    }),
                }
            }
            _ => Err(LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: "Missing either user_id or password".to_string(),
            }),
        }
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_extended_request(&mut self, request: &LdapExtendedRequest) -> Vec<LdapOp> {
        match request.name.as_str() {
            OID_PASSWORD_MODIFY => match LdapPasswordModifyRequest::try_from(request) {
                Ok(password_request) => self
                    .do_password_modification(&password_request)
                    .await
                    .unwrap_or_else(|e: LdapError| vec![make_extended_response(e.code, e.message)]),
                Err(e) => vec![make_extended_response(
                    LdapResultCode::ProtocolError,
                    format!("Error while parsing password modify request: {:#?}", e),
                )],
            },
            OID_WHOAMI => {
                let authz_id = self
                    .user_info
                    .as_ref()
                    .map(|user_info| {
                        format!(
                            "dn:uid={},ou=people,{}",
                            user_info.user.as_str(),
                            self.ldap_info.base_dn_str
                        )
                    })
                    .unwrap_or_default();
                vec![make_extended_response(LdapResultCode::Success, authz_id)]
            }
            _ => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported extended operation: {}", &request.name),
            )],
        }
    }

    async fn handle_modify_change(
        &mut self,
        user_id: UserId,
        credentials: &ValidationResults,
        user_is_admin: bool,
        change: &LdapModify,
    ) -> LdapResult<()> {
        if !change
            .modification
            .atype
            .eq_ignore_ascii_case("userpassword")
            || change.operation != LdapModifyType::Replace
        {
            return Err(LdapError {
                code: LdapResultCode::UnwillingToPerform,
                message: format!(
                    r#"Unsupported operation: `{:?}` for `{}`"#,
                    change.operation, change.modification.atype
                ),
            });
        }
        if !credentials.can_change_password(&user_id, user_is_admin) {
            return Err(LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: format!(
                    r#"User `{}` cannot modify the password of user `{}`"#,
                    &credentials.user, &user_id
                ),
            });
        }
        if let [value] = &change.modification.vals.as_slice() {
            self.change_password(self.get_opaque_handler(), user_id, value)
                .await
                .map_err(|e| LdapError {
                    code: LdapResultCode::Other,
                    message: format!("Error while changing the password: {:#?}", e),
                })?;
        } else {
            return Err(LdapError {
                code: LdapResultCode::InvalidAttributeSyntax,
                message: format!(
                    r#"Wrong number of values for password attribute: {}"#,
                    change.modification.vals.len()
                ),
            });
        }
        Ok(())
    }

    async fn handle_modify_request(
        &mut self,
        request: &LdapModifyRequest,
    ) -> LdapResult<Vec<LdapOp>> {
        let credentials = self
            .user_info
            .as_ref()
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "No user currently bound".to_string(),
            })?
            .clone();
        match get_user_id_from_distinguished_name(
            &request.dn,
            &self.ldap_info.base_dn,
            &self.ldap_info.base_dn_str,
        ) {
            Ok(uid) => {
                let user_is_admin = self
                    .backend_handler
                    .get_readable_handler(&credentials, &uid)
                    .expect("Unexpected permission error")
                    .get_user_groups(&uid)
                    .await
                    .map_err(|e| LdapError {
                        code: LdapResultCode::OperationsError,
                        message: format!("Internal error while requesting user's groups: {:#?}", e),
                    })?
                    .iter()
                    .any(|g| g.display_name == "lldap_admin".into());
                for change in &request.changes {
                    self.handle_modify_change(uid.clone(), &credentials, user_is_admin, change)
                        .await?
                }
                Ok(vec![make_modify_response(
                    LdapResultCode::Success,
                    String::new(),
                )])
            }
            Err(e) => Err(LdapError {
                code: LdapResultCode::InvalidDNSyntax,
                message: format!("Invalid username: {}", e),
            }),
        }
    }

    #[instrument(skip_all, level = "debug", fields(dn = %request.dn))]
    async fn do_modify_request(&mut self, request: &LdapModifyRequest) -> Vec<LdapOp> {
        self.handle_modify_request(request)
            .await
            .unwrap_or_else(|e: LdapError| vec![make_modify_response(e.code, e.message)])
    }

    pub async fn do_search_or_dse(
        &mut self,
        request: &LdapSearchRequest,
    ) -> LdapResult<Vec<LdapOp>> {
        if request.base.is_empty() && request.scope == LdapSearchScope::Base {
            if let LdapFilter::Present(attribute) = &request.filter {
                if attribute.eq_ignore_ascii_case("objectclass") {
                    debug!("rootDSE request");
                    return Ok(vec![
                        root_dse_response(&self.ldap_info.base_dn_str),
                        make_search_success(),
                    ]);
                }
            }
        } else if request.base == "cn=Subschema" && request.scope == LdapSearchScope::Base {
            // See RFC4512 section 4.4 "Subschema discovery"
            debug!("Schema request made");
            let backend_handler = self
                .user_info
                .as_ref()
                .and_then(|u| self.backend_handler.get_schema_only_handler(u))
                .ok_or_else(|| LdapError {
                    code: LdapResultCode::InsufficentAccessRights,
                    message: "No user currently bound".to_string(),
                })?;

            let schema = &backend_handler.get_schema().await.map_err(|e| LdapError {
                code: LdapResultCode::OperationsError,
                message: format!("Unable to get schema: {:#}", e),
            })?;
            return Ok(vec![schema_response(&schema), make_search_success()]);
        }
        self.do_search(request).await
    }

    async fn do_search_internal(
        &self,
        backend_handler: &impl UserAndGroupListerBackendHandler,
        request: &LdapSearchRequest,
        schema: &PublicSchema,
    ) -> LdapResult<InternalSearchResults> {
        let dn_parts = parse_distinguished_name(&request.base.to_ascii_lowercase())?;
        let scope = get_search_scope(&self.ldap_info.base_dn, &dn_parts, &request.scope);
        debug!(?request.base, ?scope);
        // Disambiguate the lifetimes.
        fn cast<'a, T, R>(x: T) -> T
        where
            T: Fn(&'a LdapFilter) -> R + 'a,
        {
            x
        }

        let get_user_list = cast(|filter: &LdapFilter| async {
            let need_groups = request
                .attrs
                .iter()
                .any(|s| s.eq_ignore_ascii_case("memberof"));
            get_user_list(
                &self.ldap_info,
                filter,
                need_groups,
                &request.base,
                backend_handler,
                schema,
            )
            .await
        });
        let get_group_list = cast(|filter: &LdapFilter| async {
            get_groups_list(
                &self.ldap_info,
                filter,
                &request.base,
                backend_handler,
                schema,
            )
            .await
        });
        Ok(match scope {
            SearchScope::Global => {
                let users = get_user_list(&request.filter).await;
                let groups = get_group_list(&request.filter).await;
                match (users, groups) {
                    (Ok(users), Err(e)) => {
                        warn!("Error while getting groups: {:#}", e);
                        InternalSearchResults::UsersAndGroups(users, Vec::new())
                    }
                    (Err(e), Ok(groups)) => {
                        warn!("Error while getting users: {:#}", e);
                        InternalSearchResults::UsersAndGroups(Vec::new(), groups)
                    }
                    (Err(user_error), Err(_)) => {
                        InternalSearchResults::Raw(vec![make_search_error(
                            user_error.code,
                            user_error.message,
                        )])
                    }
                    (Ok(users), Ok(groups)) => InternalSearchResults::UsersAndGroups(users, groups),
                }
            }
            SearchScope::Users => InternalSearchResults::UsersAndGroups(
                get_user_list(&request.filter).await?,
                Vec::new(),
            ),
            SearchScope::Groups => InternalSearchResults::UsersAndGroups(
                Vec::new(),
                get_group_list(&request.filter).await?,
            ),
            SearchScope::User(filter) => {
                let filter = LdapFilter::And(vec![request.filter.clone(), filter]);
                InternalSearchResults::UsersAndGroups(get_user_list(&filter).await?, Vec::new())
            }
            SearchScope::Group(filter) => {
                let filter = LdapFilter::And(vec![request.filter.clone(), filter]);
                InternalSearchResults::UsersAndGroups(Vec::new(), get_group_list(&filter).await?)
            }
            SearchScope::UserOuOnly | SearchScope::GroupOuOnly => {
                InternalSearchResults::Raw(vec![LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: request.base.clone(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "objectClass".to_owned(),
                        vals: vec![b"top".to_vec(), b"organizationalUnit".to_vec()],
                    }],
                })])
            }
            SearchScope::Unknown => {
                warn!(
                    r#"The requested search tree "{}" matches neither the user subtree "ou=people,{}" nor the group subtree "ou=groups,{}""#,
                    &request.base, &self.ldap_info.base_dn_str, &self.ldap_info.base_dn_str
                );
                InternalSearchResults::Empty
            }
            SearchScope::Invalid => {
                // Search path is not in our tree, just return an empty success.
                warn!(
                    "The specified search tree {:?} is not under the common subtree {:?}",
                    &dn_parts, &self.ldap_info.base_dn
                );
                InternalSearchResults::Empty
            }
        })
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_search(&self, request: &LdapSearchRequest) -> LdapResult<Vec<LdapOp>> {
        let user_info = self.user_info.as_ref().ok_or_else(|| LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: "No user currently bound".to_string(),
        })?;
        let backend_handler = self
            .backend_handler
            .get_user_restricted_lister_handler(user_info);

        let schema =
            PublicSchema::from(backend_handler.get_schema().await.map_err(|e| LdapError {
                code: LdapResultCode::OperationsError,
                message: format!("Unable to get schema: {:#}", e),
            })?);
        let search_results = self
            .do_search_internal(&backend_handler, request, &schema)
            .await?;
        let mut results = match search_results {
            InternalSearchResults::UsersAndGroups(users, groups) => {
                convert_users_to_ldap_op(users, &request.attrs, &self.ldap_info, &schema)
                    .chain(convert_groups_to_ldap_op(
                        groups,
                        &request.attrs,
                        &self.ldap_info,
                        &backend_handler.user_filter,
                        &schema,
                    ))
                    .collect()
            }
            InternalSearchResults::Raw(raw_results) => raw_results,
            InternalSearchResults::Empty => Vec::new(),
        };
        if !matches!(results.last(), Some(LdapOp::SearchResultDone(_))) {
            results.push(make_search_success());
        }
        Ok(results)
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_create_user(&self, request: LdapAddRequest) -> LdapResult<Vec<LdapOp>> {
        let backend_handler = self
            .user_info
            .as_ref()
            .and_then(|u| self.backend_handler.get_admin_handler(u))
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "Unauthorized write".to_string(),
            })?;
        let user_id = get_user_id_from_distinguished_name(
            &request.dn,
            &self.ldap_info.base_dn,
            &self.ldap_info.base_dn_str,
        )?;
        fn parse_attribute(mut attr: LdapPartialAttribute) -> LdapResult<(String, Vec<u8>)> {
            if attr.vals.len() > 1 {
                Err(LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!("Expected a single value for attribute {}", attr.atype),
                })
            } else {
                attr.atype.make_ascii_lowercase();
                match attr.vals.pop() {
                    Some(val) => Ok((attr.atype, val)),
                    None => Err(LdapError {
                        code: LdapResultCode::ConstraintViolation,
                        message: format!("Missing value for attribute {}", attr.atype),
                    }),
                }
            }
        }
        let attributes: HashMap<String, Vec<u8>> = request
            .attributes
            .into_iter()
            .filter(|a| !a.atype.eq_ignore_ascii_case("objectclass"))
            .map(parse_attribute)
            .collect::<LdapResult<_>>()?;
        fn decode_attribute_value(val: &[u8]) -> LdapResult<String> {
            std::str::from_utf8(val)
                .map_err(|e| LdapError {
                    code: LdapResultCode::ConstraintViolation,
                    message: format!(
                        "Attribute value is invalid UTF-8: {:#?} (value {:?})",
                        e, val
                    ),
                })
                .map(str::to_owned)
        }
        let get_attribute = |name| {
            attributes
                .get(name)
                .map(Vec::as_slice)
                .map(decode_attribute_value)
        };
        let make_encoded_attribute = |name: &str, typ: AttributeType, value: String| {
            Ok(Attribute {
                name: AttributeName::from(name),
                value: deserialize::deserialize_attribute_value(&[value], typ, false).map_err(
                    |e| LdapError {
                        code: LdapResultCode::ConstraintViolation,
                        message: format!("Invalid attribute value: {}", e),
                    },
                )?,
            })
        };
        let mut new_user_attributes: Vec<Attribute> = Vec::new();
        if let Some(first_name) = get_attribute("givenname").transpose()? {
            new_user_attributes.push(make_encoded_attribute(
                "first_name",
                AttributeType::String,
                first_name,
            )?);
        }
        if let Some(last_name) = get_attribute("sn").transpose()? {
            new_user_attributes.push(make_encoded_attribute(
                "last_name",
                AttributeType::String,
                last_name,
            )?);
        }
        if let Some(avatar) = get_attribute("avatar").transpose()? {
            new_user_attributes.push(make_encoded_attribute(
                "avatar",
                AttributeType::JpegPhoto,
                avatar,
            )?);
        }
        backend_handler
            .create_user(CreateUserRequest {
                user_id,
                email: Email::from(
                    get_attribute("mail")
                        .or_else(|| get_attribute("email"))
                        .transpose()?
                        .unwrap_or_default(),
                ),
                display_name: get_attribute("cn").transpose()?,
                attributes: new_user_attributes,
            })
            .await
            .map_err(|e| LdapError {
                code: LdapResultCode::OperationsError,
                message: format!("Could not create user: {:#?}", e),
            })?;
        Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_compare(&mut self, request: LdapCompareRequest) -> LdapResult<Vec<LdapOp>> {
        let req = make_search_request::<String>(
            &self.ldap_info.base_dn_str,
            LdapFilter::Equality("dn".to_string(), request.dn.to_string()),
            vec![request.atype.clone()],
        );
        let entries = self.do_search(&req).await?;
        if entries.len() > 2 {
            // SearchResultEntry + SearchResultDone
            return Err(LdapError {
                code: LdapResultCode::OperationsError,
                message: "Too many search results".to_string(),
            });
        }
        let requested_attribute = AttributeName::from(&request.atype);
        match entries.first() {
            Some(LdapOp::SearchResultEntry(entry)) => {
                let available = entry.attributes.iter().any(|attr| {
                    AttributeName::from(&attr.atype) == requested_attribute
                        && attr.vals.contains(&request.val)
                });
                Ok(vec![LdapOp::CompareResult(LdapResultOp {
                    code: if available {
                        LdapResultCode::CompareTrue
                    } else {
                        LdapResultCode::CompareFalse
                    },
                    matcheddn: request.dn,
                    message: "".to_string(),
                    referral: vec![],
                })])
            }
            Some(LdapOp::SearchResultDone(_)) => Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::NoSuchObject,
                matcheddn: self.ldap_info.base_dn_str.clone(),
                message: "".to_string(),
                referral: vec![],
            })]),
            None => Err(LdapError {
                code: LdapResultCode::OperationsError,
                message: "Search request returned nothing".to_string(),
            }),
            _ => Err(LdapError {
                code: LdapResultCode::OperationsError,
                message: "Unexpected results from search".to_string(),
            }),
        }
    }

    pub async fn handle_ldap_message(&mut self, ldap_op: LdapOp) -> Option<Vec<LdapOp>> {
        Some(match ldap_op {
            LdapOp::BindRequest(request) => {
                let (code, message) = self.do_bind(&request).await;
                vec![LdapOp::BindResponse(LdapBindResponse {
                    res: LdapResultOp {
                        code,
                        matcheddn: "".to_string(),
                        message,
                        referral: vec![],
                    },
                    saslcreds: None,
                })]
            }
            LdapOp::SearchRequest(request) => self
                .do_search_or_dse(&request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            LdapOp::UnbindRequest => {
                debug!(
                    "Unbind request for {}",
                    self.user_info
                        .as_ref()
                        .map(|u| u.user.as_str())
                        .unwrap_or("<not bound>"),
                );
                self.user_info = None;
                // No need to notify on unbind (per rfc4511)
                return None;
            }
            LdapOp::ModifyRequest(request) => self.do_modify_request(&request).await,
            LdapOp::ExtendedRequest(request) => self.do_extended_request(&request).await,
            LdapOp::AddRequest(request) => self
                .do_create_user(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_add_error(e.code, e.message)]),
            LdapOp::CompareRequest(request) => self
                .do_compare(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            op => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported operation: {:#?}", op),
            )],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::test_utils::{setup_default_schema, MockTestBackendHandler};
    use chrono::TimeZone;
    use ldap3_proto::proto::{
        LdapDerefAliases, LdapSearchScope, LdapSubstringFilter, LdapWhoamiRequest,
    };
    use lldap_domain::{
        schema::{AttributeList, AttributeSchema, Schema},
        types::*,
        uuid,
    };
    use lldap_domain_handlers::handler::*;
    use lldap_domain_model::model::UserColumn;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;
    use tokio;

    fn make_user_search_request<S: Into<String>>(
        filter: LdapFilter,
        attrs: Vec<S>,
    ) -> LdapSearchRequest {
        make_search_request::<S>("ou=people,Dc=example,dc=com", filter, attrs)
    }

    fn make_group_search_request<S: Into<String>>(
        filter: LdapFilter,
        attrs: Vec<S>,
    ) -> LdapSearchRequest {
        make_search_request::<S>("ou=groups,dc=example,dc=com", filter, attrs)
    }

    async fn setup_bound_handler_with_group(
        mut mock: MockTestBackendHandler,
        group: &str,
    ) -> LdapHandler<MockTestBackendHandler> {
        mock.expect_bind()
            .with(eq(BindRequest {
                name: UserId::new("test"),
                password: "pass".to_string(),
            }))
            .return_once(|_| Ok(()));
        let group = group.to_string();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("test")))
            .return_once(|_| {
                let mut set = HashSet::new();
                set.insert(GroupDetails {
                    group_id: GroupId(42),
                    display_name: group.into(),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    attributes: Vec::new(),
                });
                Ok(set)
            });
        setup_default_schema(&mut mock);
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=Example,dc=com");
        let request = LdapBindRequest {
            dn: "uid=test,ou=people,dc=example,dc=coM".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
        );
        ldap_handler
    }

    async fn setup_bound_readonly_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_strict_readonly").await
    }

    async fn setup_bound_password_manager_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_password_manager").await
    }

    async fn setup_bound_admin_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_admin").await
    }

    #[tokio::test]
    async fn test_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(lldap_domain_handlers::handler::BindRequest {
                name: UserId::new("bob"),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(HashSet::new()));
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=eXample,dc=com");

        let request = LdapOp::BindRequest(LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        });
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![LdapOp::BindResponse(LdapBindResponse {
                res: LdapResultOp {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                },
                saslcreds: None,
            })]),
        );
    }

    #[tokio::test]
    async fn test_admin_bind() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_bind()
            .with(eq(lldap_domain_handlers::handler::BindRequest {
                name: UserId::new("test"),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_get_user_groups()
            .with(eq(UserId::new("test")))
            .return_once(|_| {
                let mut set = HashSet::new();
                set.insert(GroupDetails {
                    group_id: GroupId(42),
                    display_name: "lldap_admin".into(),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                    attributes: Vec::new(),
                });
                Ok(set)
            });
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");

        let request = LdapBindRequest {
            dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::Success
        );
    }

    #[tokio::test]
    async fn test_search_regular_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![
                    true.into(),
                    UserRequestFilter::UserId(UserId::new("test")),
                ]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| {
                Ok(vec![UserAndGroups {
                    user: User {
                        user_id: UserId::new("test"),
                        ..Default::default()
                    },
                    groups: None,
                }])
            });
        let mut ldap_handler = setup_bound_handler_with_group(mock, "regular").await;

        let request =
            make_user_search_request::<String>(LdapFilter::And(vec![]), vec!["1.1".to_string()]);
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success()
            ]),
        );
    }

    #[tokio::test]
    async fn test_search_readonly_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(true.into())), eq(false))
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request =
            make_user_search_request::<String>(LdapFilter::And(vec![]), vec!["1.1".to_string()]);
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }

    #[tokio::test]
    async fn test_search_member_of() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(true.into())), eq(true))
            .times(1)
            .return_once(|_, _| {
                Ok(vec![UserAndGroups {
                    user: User {
                        user_id: UserId::new("bob"),
                        ..Default::default()
                    },
                    groups: Some(vec![GroupDetails {
                        group_id: GroupId(42),
                        display_name: "rockstars".into(),
                        creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                        uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
                        attributes: Vec::new(),
                    }]),
                }])
            });
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = make_user_search_request::<String>(
            LdapFilter::And(vec![]),
            vec!["memberOf".to_string()],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "memberOf".to_string(),
                        vals: vec![b"cn=rockstars,ou=groups,dc=example,dc=com".to_vec()]
                    }],
                }),
                make_search_success(),
            ]),
        );
    }

    #[tokio::test]
    async fn test_search_user_as_scope() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![
                    true.into(),
                    UserRequestFilter::UserId(UserId::new("bob")),
                ]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = LdapSearchRequest {
            base: "uid=bob,ou=people,Dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::And(vec![]),
            attrs: vec!["1.1".to_string()],
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }

    #[tokio::test]
    async fn test_bind_invalid_dn() {
        let mock = MockTestBackendHandler::new();
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");

        let request = LdapBindRequest {
            dn: "cn=bob,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob,ou=groups,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=fr".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
        let request = LdapBindRequest {
            dn: "uid=bob=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await.0,
            LdapResultCode::NamingViolation,
        );
    }

    #[test]
    fn test_is_subtree() {
        let subtree1 = &[
            ("ou".to_string(), "people".to_string()),
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        let root = &[
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        assert!(is_subtree(subtree1, root));
        assert!(!is_subtree(&[], root));
    }

    #[test]
    fn test_parse_distinguished_name() {
        let parsed_dn = &[
            ("ou".to_string(), "people".to_string()),
            ("dc".to_string(), "example".to_string()),
            ("dc".to_string(), "com".to_string()),
        ];
        assert_eq!(
            parse_distinguished_name("ou=people,dc=example,dc=com").expect("parsing failed"),
            parsed_dn
        );
        assert_eq!(
            parse_distinguished_name(" ou  = people , dc = example , dc =  com ")
                .expect("parsing failed"),
            parsed_dn
        );
    }

    #[tokio::test]
    async fn test_search_users() {
        use chrono::prelude::*;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().times(1).return_once(|_, _| {
            Ok(vec![
                UserAndGroups {
                    user: User {
                        user_id: UserId::new("bob_1"),
                        email: "bob@bobmail.bob".into(),
                        display_name: Some("Bôb Böbberson".to_string()),
                        uuid: uuid!("698e1d5f-7a40-3151-8745-b9b8a37839da"),
                        attributes: vec![
                            Attribute {
                                name: "first_name".into(),
                                value: "Bôb".to_string().into(),
                            },
                            Attribute {
                                name: "last_name".into(),
                                value: "Böbberson".to_string().into(),
                            },
                        ],
                        ..Default::default()
                    },
                    groups: None,
                },
                UserAndGroups {
                    user: User {
                        user_id: UserId::new("jim"),
                        email: "jim@cricket.jim".into(),
                        display_name: Some("Jimminy Cricket".to_string()),
                        attributes: vec![
                            Attribute {
                                name: "avatar".into(),
                                value: JpegPhoto::for_tests().into(),
                            },
                            Attribute {
                                name: "first_name".into(),
                                value: "Jim".to_string().into(),
                            },
                            Attribute {
                                name: "last_name".into(),
                                value: "Cricket".to_string().into(),
                            },
                        ],
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                        creation_date: Utc
                            .with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
                            .unwrap()
                            .naive_utc(),
                    },
                    groups: None,
                },
            ])
        });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![]),
            vec![
                "objectClass",
                "dn",
                "uid",
                "mail",
                "givenName",
                "sn",
                "cn",
                "createTimestamp",
                "entryUuid",
                "jpegPhoto",
            ],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Bôb Böbberson".to_string().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "createTimestamp".to_string(),
                            vals: vec![b"1970-01-01T00:00:00+00:00".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"698e1d5f-7a40-3151-8745-b9b8a37839da".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec!["Bôb".to_string().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec![b"bob@bobmail.bob".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                b"inetOrgPerson".to_vec(),
                                b"posixAccount".to_vec(),
                                b"mailAccount".to_vec(),
                                b"person".to_vec(),
                                b"customUserClass".to_vec(),
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec!["Böbberson".to_string().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec![b"bob_1".to_vec()]
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=jim,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"Jimminy Cricket".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "createTimestamp".to_string(),
                            vals: vec![b"2014-07-08T09:10:11+00:00".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec![b"Jim".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "jpegPhoto".to_string(),
                            vals: vec![JpegPhoto::for_tests().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "mail".to_string(),
                            vals: vec![b"jim@cricket.jim".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                b"inetOrgPerson".to_vec(),
                                b"posixAccount".to_vec(),
                                b"mailAccount".to_vec(),
                                b"person".to_vec(),
                                b"customUserClass".to_vec(),
                            ]
                        },
                        LdapPartialAttribute {
                            atype: "sn".to_string(),
                            vals: vec![b"Cricket".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_string(),
                            vals: vec![b"jim".to_vec()]
                        },
                    ],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(true.into())))
            .times(1)
            .return_once(|_| {
                Ok(vec![
                    Group {
                        id: GroupId(1),
                        display_name: "group_1".into(),
                        creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                        users: vec![UserId::new("bob"), UserId::new("john")],
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                        attributes: Vec::new(),
                    },
                    Group {
                        id: GroupId(3),
                        display_name: "BestGroup".into(),
                        creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                        users: vec![UserId::new("john")],
                        uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                        attributes: Vec::new(),
                    },
                ])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::And(vec![]),
            vec![
                "objectClass",
                "dn",
                "cn",
                "uniqueMember",
                "entryUuid",
                "entryDN",
            ],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"group_1".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryDN".to_string(),
                            vals: vec![b"uid=group_1,ou=groups,dc=example,dc=com".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(),]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec![
                                b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
                                b"uid=john,ou=people,dc=example,dc=com".to_vec(),
                            ]
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=BestGroup,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"BestGroup".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "entryDN".to_string(),
                            vals: vec![b"uid=BestGroup,ou=groups,dc=example,dc=com".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "entryUuid".to_string(),
                            vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(),]
                        },
                        LdapPartialAttribute {
                            atype: "uniqueMember".to_string(),
                            vals: vec![b"uid=john,ou=people,dc=example,dc=com".to_vec()]
                        },
                    ],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_by_groupid() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::GroupId(GroupId(1)))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    id: GroupId(1),
                    display_name: "group_1".into(),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![UserId::new("bob"), UserId::new("john")],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Equality("groupid".to_string(), "1".to_string()),
            vec!["dn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![
                GroupRequestFilter::DisplayName("group_1".into()),
                GroupRequestFilter::Member(UserId::new("bob")),
                GroupRequestFilter::DisplayName("rockstars".into()),
                false.into(),
                GroupRequestFilter::Uuid(uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc")),
                true.into(),
                true.into(),
                true.into(),
                true.into(),
                GroupRequestFilter::Not(Box::new(false.into())),
                false.into(),
                GroupRequestFilter::DisplayNameSubString(SubStringFilter {
                    initial: Some("iNIt".to_owned()),
                    any: vec!["1".to_owned(), "2aA".to_owned()],
                    final_: Some("finAl".to_owned()),
                }),
            ]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".into(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::And(vec![
                LdapFilter::Equality("cN".to_string(), "Group_1".to_string()),
                LdapFilter::Equality(
                    "uniqueMember".to_string(),
                    "uid=bob,ou=peopLe,Dc=eXample,dc=com".to_string(),
                ),
                LdapFilter::Equality(
                    "dn".to_string(),
                    "uid=rockstars,ou=groups,dc=example,dc=com".to_string(),
                ),
                LdapFilter::Equality(
                    "dn".to_string(),
                    "uid=rockstars,ou=people,dc=example,dc=com".to_string(),
                ),
                LdapFilter::Equality(
                    "uuid".to_string(),
                    "04ac75e0-2900-3e21-926c-2f732c26b3fc".to_string(),
                ),
                LdapFilter::Equality("obJEctclass".to_string(), "groupofUniqueNames".to_string()),
                LdapFilter::Equality("objectclass".to_string(), "groupOfNames".to_string()),
                LdapFilter::Present("objectclass".to_string()),
                LdapFilter::Present("dn".to_string()),
                LdapFilter::Not(Box::new(LdapFilter::Present(
                    "random_attribUte".to_string(),
                ))),
                LdapFilter::Equality("unknown_attribute".to_string(), "randomValue".to_string()),
                LdapFilter::Substring(
                    "cn".to_owned(),
                    LdapSubstringFilter {
                        initial: Some("iNIt".to_owned()),
                        any: vec!["1".to_owned(), "2aA".to_owned()],
                        final_: Some("finAl".to_owned()),
                    },
                ),
            ]),
            vec!["1.1"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_2() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::Or(vec![
                GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                    "group_2".into(),
                ))),
            ]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".into(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Or(vec![LdapFilter::Not(Box::new(LdapFilter::Equality(
                "displayname".to_string(),
                "group_2".to_string(),
            )))]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![b"group_1".to_vec()]
                    },],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_3() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::Or(vec![
                GroupRequestFilter::AttributeEquality(
                    AttributeName::from("attr"),
                    "TEST".to_string().into(),
                ),
                GroupRequestFilter::AttributeEquality(
                    AttributeName::from("attr"),
                    "test".to_string().into(),
                ),
            ]))))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    display_name: "group_1".into(),
                    id: GroupId(1),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: vec![Attribute {
                        name: "Attr".into(),
                        value: "TEST".to_string().into(),
                    }],
                }])
            });
        mock.expect_get_schema().returning(|| {
            Ok(Schema {
                user_attributes: AttributeList {
                    attributes: Vec::new(),
                },
                group_attributes: AttributeList {
                    attributes: vec![AttributeSchema {
                        name: "Attr".into(),
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: false,
                        is_readonly: false,
                    }],
                },
                extra_user_object_classes: Vec::new(),
                extra_group_object_classes: Vec::new(),
            })
        });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Equality("Attr".to_string(), "TEST".to_string()),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![b"group_1".to_vec()]
                    },],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_group_as_scope() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::And(vec![
                true.into(),
                GroupRequestFilter::DisplayName("rockstars".into()),
            ]))))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = LdapSearchRequest {
            base: "uid=rockstars,ou=groups,Dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::And(vec![]),
            attrs: vec!["1.1".to_string()],
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }

    #[tokio::test]
    async fn test_search_groups_unsupported_substring() {
        let mut ldap_handler = setup_bound_readonly_handler(MockTestBackendHandler::new()).await;
        let request = make_group_search_request(
            LdapFilter::Substring("member".to_owned(), LdapSubstringFilter::default()),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError {
                code: LdapResultCode::UnwillingToPerform,
                message: r#"Unsupported group attribute for substring filter: "member""#.to_owned()
            })
        );
    }

    #[tokio::test]
    async fn test_search_groups_missing_attribute_substring() {
        let request = make_group_search_request(
            LdapFilter::Substring("nonexistent".to_owned(), LdapSubstringFilter::default()),
            vec!["cn"],
        );
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(false.into())))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()]),
        );
    }

    #[tokio::test]
    async fn test_search_groups_error() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_groups()
            .with(eq(Some(GroupRequestFilter::Or(vec![
                GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                    "group_2".into(),
                ))),
            ]))))
            .times(1)
            .return_once(|_| {
                Err(lldap_domain_model::error::DomainError::InternalError(
                    "Error getting groups".to_string(),
                ))
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_group_search_request(
            LdapFilter::Or(vec![LdapFilter::Not(Box::new(LdapFilter::Equality(
                "displayname".to_string(),
                "group_2".to_string(),
            )))]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError{
                code: LdapResultCode::Other,
                message: r#"Error while listing groups "ou=groups,dc=example,dc=com": Internal error: `Error getting groups`"#.to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_search_groups_filter_error() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = make_group_search_request(
            LdapFilter::And(vec![LdapFilter::Approx(
                "whatever".to_owned(),
                "value".to_owned(),
            )]),
            vec!["cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError {
                code: LdapResultCode::UnwillingToPerform,
                message: r#"Unsupported group filter: Approx("whatever", "value")"#.to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_search_filters() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![UserRequestFilter::Or(
                    vec![
                        UserRequestFilter::Not(Box::new(UserRequestFilter::UserId(UserId::new(
                            "bob",
                        )))),
                        UserRequestFilter::UserId("bob_1".to_string().into()),
                        false.into(),
                        true.into(),
                        false.into(),
                        true.into(),
                        true.into(),
                        false.into(),
                        UserRequestFilter::Or(vec![
                            UserRequestFilter::AttributeEquality(
                                AttributeName::from("first_name"),
                                "FirstName".to_string().into(),
                            ),
                            UserRequestFilter::AttributeEquality(
                                AttributeName::from("first_name"),
                                "firstname".to_string().into(),
                            ),
                        ]),
                        false.into(),
                        UserRequestFilter::UserIdSubString(SubStringFilter {
                            initial: Some("iNIt".to_owned()),
                            any: vec!["1".to_owned(), "2aA".to_owned()],
                            final_: Some("finAl".to_owned()),
                        }),
                        UserRequestFilter::SubString(
                            UserColumn::DisplayName,
                            SubStringFilter {
                                initial: Some("iNIt".to_owned()),
                                any: vec!["1".to_owned(), "2aA".to_owned()],
                                final_: Some("finAl".to_owned()),
                            },
                        ),
                    ],
                )]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![LdapFilter::Or(vec![
                LdapFilter::Not(Box::new(LdapFilter::Equality(
                    "uid".to_string(),
                    "bob".to_string(),
                ))),
                LdapFilter::Equality(
                    "dn".to_string(),
                    "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                ),
                LdapFilter::Equality(
                    "dn".to_string(),
                    "uid=bob_1,ou=groups,dc=example,dc=com".to_string(),
                ),
                LdapFilter::Equality("objectclass".to_string(), "persOn".to_string()),
                LdapFilter::Equality("objectclass".to_string(), "other".to_string()),
                LdapFilter::Present("objectClass".to_string()),
                LdapFilter::Present("uid".to_string()),
                LdapFilter::Present("unknown".to_string()),
                LdapFilter::Equality("givenname".to_string(), "FirstName".to_string()),
                LdapFilter::Equality("unknown_attribute".to_string(), "randomValue".to_string()),
                LdapFilter::Substring(
                    "uid".to_owned(),
                    LdapSubstringFilter {
                        initial: Some("iNIt".to_owned()),
                        any: vec!["1".to_owned(), "2aA".to_owned()],
                        final_: Some("finAl".to_owned()),
                    },
                ),
                LdapFilter::Substring(
                    "displayName".to_owned(),
                    LdapSubstringFilter {
                        initial: Some("iNIt".to_owned()),
                        any: vec!["1".to_owned(), "2aA".to_owned()],
                        final_: Some("finAl".to_owned()),
                    },
                ),
            ])]),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_search_unsupported_substring_filter() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = make_user_search_request(
            LdapFilter::Substring(
                "uuid".to_owned(),
                LdapSubstringFilter {
                    initial: Some("iNIt".to_owned()),
                    any: vec!["1".to_owned(), "2aA".to_owned()],
                    final_: Some("finAl".to_owned()),
                },
            ),
            vec!["objectClass"],
        );
        ldap_handler.do_search_or_dse(&request).await.unwrap_err();
        let request = make_user_search_request(
            LdapFilter::Substring(
                "givenname".to_owned(),
                LdapSubstringFilter {
                    initial: Some("iNIt".to_owned()),
                    any: vec!["1".to_owned(), "2aA".to_owned()],
                    final_: Some("finAl".to_owned()),
                },
            ),
            vec!["objectClass"],
        );
        ldap_handler.do_search_or_dse(&request).await.unwrap_err();
    }

    #[tokio::test]
    async fn test_search_member_of_filter() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::MemberOf("group_1".into()))),
                eq(false),
            )
            .times(2)
            .returning(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::Equality(
                "memberOf".to_string(),
                "cn=group_1, ou=groups, dc=example,dc=com".to_string(),
            ),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
        let request = make_user_search_request(
            LdapFilter::Equality("memberOf".to_string(), "group_1".to_string()),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }
    #[tokio::test]
    async fn test_search_member_of_filter_error() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(UserRequestFilter::from(false))), eq(false))
            .times(1)
            .returning(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::Equality(
                "memberOf".to_string(),
                "cn=mygroup,dc=example,dc=com".to_string(),
            ),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            // The error is ignored, a warning is printed.
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_search_filters_lowercase() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![UserRequestFilter::Or(
                    vec![UserRequestFilter::Not(Box::new(
                        UserRequestFilter::Equality(UserColumn::DisplayName, "bob".to_string()),
                    ))],
                )]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| {
                Ok(vec![UserAndGroups {
                    user: User {
                        user_id: UserId::new("bob_1"),
                        ..Default::default()
                    },
                    groups: None,
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::And(vec![LdapFilter::Or(vec![LdapFilter::Not(Box::new(
                LdapFilter::Equality("displayname".to_string(), "bob".to_string()),
            ))])]),
            vec!["objectclass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![
                            b"inetOrgPerson".to_vec(),
                            b"posixAccount".to_vec(),
                            b"mailAccount".to_vec(),
                            b"person".to_vec(),
                            b"customUserClass".to_vec(),
                        ]
                    },]
                }),
                make_search_success()
            ])
        );
    }

    #[tokio::test]
    async fn test_search_filters_custom_object_class() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(UserRequestFilter::from(true))), eq(false))
            .times(1)
            .return_once(|_, _| {
                Ok(vec![UserAndGroups {
                    user: User {
                        user_id: UserId::new("bob_1"),
                        ..Default::default()
                    },
                    groups: None,
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::Equality("objectClass".to_owned(), "CUSTOMuserCLASS".to_owned()),
            vec!["objectclass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![
                            b"inetOrgPerson".to_vec(),
                            b"posixAccount".to_vec(),
                            b"mailAccount".to_vec(),
                            b"person".to_vec(),
                            b"customUserClass".to_vec(),
                        ]
                    },]
                }),
                make_search_success()
            ])
        );
    }

    #[tokio::test]
    async fn test_search_both() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().times(1).return_once(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob_1"),
                    email: "bob@bobmail.bob".into(),
                    display_name: Some("Bôb Böbberson".to_string()),
                    attributes: vec![
                        Attribute {
                            name: "first_name".into(),
                            value: "Bôb".to_string().into(),
                        },
                        Attribute {
                            name: "last_name".to_string().into(),
                            value: "Böbberson".to_string().into(),
                        },
                    ],
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups()
            .with(eq(Some(true.into())))
            .times(1)
            .return_once(|_| {
                Ok(vec![Group {
                    id: GroupId(1),
                    display_name: "group_1".into(),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![UserId::new("bob"), UserId::new("john")],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass", "dn", "cn"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec!["Bôb Böbberson".to_string().into_bytes()]
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![
                                b"inetOrgPerson".to_vec(),
                                b"posixAccount".to_vec(),
                                b"mailAccount".to_vec(),
                                b"person".to_vec(),
                                b"customUserClass".to_vec(),
                            ],
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![b"group_1".to_vec()]
                        },
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec![b"groupOfUniqueNames".to_vec(),]
                        },
                    ],
                }),
                make_search_success(),
            ])
        );
    }

    #[tokio::test]
    async fn test_search_wildcards() {
        let mut mock = MockTestBackendHandler::new();

        mock.expect_list_users().returning(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob_1"),
                    email: "bob@bobmail.bob".into(),
                    display_name: Some("Bôb Böbberson".to_string()),
                    attributes: vec![
                        Attribute {
                            name: "avatar".into(),
                            value: JpegPhoto::for_tests().into(),
                        },
                        Attribute {
                            name: "last_name".into(),
                            value: "Böbberson".to_string().into(),
                        },
                    ],
                    uuid: uuid!("b4ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups()
            .with(eq(Some(true.into())))
            .returning(|_| {
                Ok(vec![Group {
                    id: GroupId(1),
                    display_name: "group_1".into(),
                    creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                    users: vec![UserId::new("bob"), UserId::new("john")],
                    uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                    attributes: Vec::new(),
                }])
            });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;

        // Test simple wildcard
        let request =
            make_search_request("dc=example,dc=com", LdapFilter::And(vec![]), vec!["*", "+"]);

        // all: "objectclass", "dn", "uid", "mail", "givenname", "sn", "cn"
        // Operational: "createtimestamp"

        let expected_result = Ok(vec![
            LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: "uid=bob_1,ou=people,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "avatar".to_string(),
                        vals: vec![JpegPhoto::for_tests().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["Bôb Böbberson".to_string().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "createtimestamp".to_string(),
                        vals: vec![chrono::Utc
                            .timestamp_opt(0, 0)
                            .unwrap()
                            .to_rfc3339()
                            .into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "entryuuid".to_string(),
                        vals: vec![b"b4ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "jpegPhoto".to_string(),
                        vals: vec![JpegPhoto::for_tests().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "last_name".to_string(),
                        vals: vec!["Böbberson".to_string().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "mail".to_string(),
                        vals: vec![b"bob@bobmail.bob".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![
                            b"inetOrgPerson".to_vec(),
                            b"posixAccount".to_vec(),
                            b"mailAccount".to_vec(),
                            b"person".to_vec(),
                            b"customUserClass".to_vec(),
                        ],
                    },
                    LdapPartialAttribute {
                        atype: "sn".to_string(),
                        vals: vec!["Böbberson".to_string().into_bytes()],
                    },
                    LdapPartialAttribute {
                        atype: "uid".to_string(),
                        vals: vec![b"bob_1".to_vec()],
                    },
                ],
            }),
            // "objectclass", "dn", "uid", "cn", "member", "uniquemember"
            LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: "cn=group_1,ou=groups,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![b"group_1".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "entryuuid".to_string(),
                        vals: vec![b"04ac75e0-2900-3e21-926c-2f732c26b3fc".to_vec()],
                    },
                    //member / uniquemember : "uid={},ou=people,{}"
                    LdapPartialAttribute {
                        atype: "member".to_string(),
                        vals: vec![
                            b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
                            b"uid=john,ou=people,dc=example,dc=com".to_vec(),
                        ],
                    },
                    LdapPartialAttribute {
                        atype: "objectclass".to_string(),
                        vals: vec![b"groupOfUniqueNames".to_vec()],
                    },
                    // UID
                    LdapPartialAttribute {
                        atype: "uid".to_string(),
                        vals: vec![b"group_1".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "uniquemember".to_string(),
                        vals: vec![
                            b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
                            b"uid=john,ou=people,dc=example,dc=com".to_vec(),
                        ],
                    },
                ],
            }),
            make_search_success(),
        ]);

        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            expected_result
        );

        let request2 = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectclass", "obJEctclaSS", "dn", "*", "*"],
        );

        assert_eq!(
            ldap_handler.do_search_or_dse(&request2).await,
            expected_result
        );

        let request3 = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["*", "+", "+"],
        );

        assert_eq!(
            ldap_handler.do_search_or_dse(&request3).await,
            expected_result
        );

        let request4 =
            make_search_request("dc=example,dc=com", LdapFilter::And(vec![]), vec![""; 0]);

        assert_eq!(
            ldap_handler.do_search_or_dse(&request4).await,
            expected_result
        );

        let request5 = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectclass", "dn", "uid", "*"],
        );

        assert_eq!(
            ldap_handler.do_search_or_dse(&request5).await,
            expected_result
        );
    }

    #[tokio::test]
    async fn test_search_wrong_base() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = make_search_request(
            "ou=users,dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_search_unsupported_filters() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = make_user_search_request(
            LdapFilter::Approx("uid".to_owned(), "value".to_owned()),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Err(LdapError {
                code: LdapResultCode::UnwillingToPerform,
                message: r#"Unsupported user filter: Approx("uid", "value")"#.to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_password_change() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
        use lldap_auth::*;
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password".as_bytes(), &mut rng)
                .unwrap();
        let request = registration::ClientRegistrationStartRequest {
            username: "bob".into(),
            registration_start_request: registration_start_request.message,
        };
        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        )
        .unwrap();
        mock.expect_registration_start().times(1).return_once(|_| {
            Ok(registration::ServerRegistrationStartResponse {
                server_data: "".to_string(),
                registration_response: start_response.message,
            })
        });
        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_whoami_empty() {
        let mut ldap_handler =
            LdapHandler::new_for_tests(MockTestBackendHandler::new(), "dc=example,dc=com");
        let request = LdapOp::ExtendedRequest(LdapWhoamiRequest {}.into());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_whoami_bound() {
        let mock = MockTestBackendHandler::new();
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::ExtendedRequest(LdapWhoamiRequest {}.into());
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "dn:uid=test,ou=people,dc=example,dc=com".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_modify_request() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
        use lldap_auth::*;
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password".as_bytes(), &mut rng)
                .unwrap();
        let request = registration::ClientRegistrationStartRequest {
            username: "bob".into(),
            registration_start_request: registration_start_request.message,
        };
        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        )
        .unwrap();
        mock.expect_registration_start().times(1).return_once(|_| {
            Ok(registration::ServerRegistrationStartResponse {
                server_data: "".to_string(),
                registration_response: start_response.message,
            })
        });
        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::ModifyRequest(LdapModifyRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: LdapPartialAttribute {
                    atype: "userPassword".to_owned(),
                    vals: vec!["password".as_bytes().to_vec()],
                },
            }],
        });
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_modify_response(
                LdapResultCode::Success,
                "".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_password_manager() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
        use lldap_auth::*;
        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password".as_bytes(), &mut rng)
                .unwrap();
        let request = registration::ClientRegistrationStartRequest {
            username: "bob".into(),
            registration_start_request: registration_start_request.message,
        };
        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        )
        .unwrap();
        mock.expect_registration_start().times(1).return_once(|_| {
            Ok(registration::ServerRegistrationStartResponse {
                server_data: "".to_string(),
                registration_response: start_response.message,
            })
        });
        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(()));
        let mut ldap_handler = setup_bound_password_manager_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_errors() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(HashSet::new()));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: None,
                old_password: None,
                new_password: None,
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::ConstraintViolation,
                "Missing either user_id or password".to_string(),
            )])
        );
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=groups,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::InvalidDNSyntax,
                r#"Invalid username: Unexpected DN format. Got "uid=bob,ou=groups,ou=people,dc=example,dc=com", expected: "uid=id,ou=people,dc=example,dc=com""#.to_string(),
            )])
        );
        let request = LdapOp::ExtendedRequest(LdapExtendedRequest {
            name: "test".to_string(),
            value: None,
        });
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                "Unsupported extended operation: test".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_unauthorized_password_manager() {
        let mut mock = MockTestBackendHandler::new();
        let mut groups = HashSet::new();
        groups.insert(GroupDetails {
            group_id: GroupId(0),
            display_name: "lldap_admin".into(),
            creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
            uuid: uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),
            attributes: Vec::new(),
        });
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .times(1)
            .return_once(|_| Ok(groups));
        let mut ldap_handler = setup_bound_password_manager_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: Some("pass".to_string()),
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::InsufficentAccessRights,
                "User `test` cannot modify the password of user `bob`".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_unauthorized_readonly() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .times(1)
            .return_once(|_| Ok(HashSet::new()));
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;
        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: Some("pass".to_string()),
                new_password: Some("password".to_string()),
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::InsufficentAccessRights,
                "User `test` cannot modify the password of user `bob`".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_search_root_dse() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = LdapSearchRequest {
            base: "".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".to_string()),
            attrs: vec!["supportedExtension".to_string()],
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                root_dse_response("dc=example,dc=com"),
                make_search_success()
            ])
        );
    }

    #[tokio::test]
    async fn test_subschema_response() {
        let mut ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;

        let backend_handler = ldap_handler
            .user_info
            .as_ref()
            .and_then(|u| ldap_handler.backend_handler.get_schema_only_handler(u))
            .unwrap();
        let schema = &backend_handler.get_schema().await.unwrap();

        let request = LdapSearchRequest {
            base: "cn=Subschema".to_string(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".to_string()),
            attrs: vec!["supportedExtension".to_string()],
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![schema_response(&schema), make_search_success()])
        )
    }

    #[tokio::test]
    async fn test_create_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "".into(),
                display_name: Some("Bob".to_string()),
                ..Default::default()
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bob".to_vec()],
            }],
        };
        assert_eq!(
            ldap_handler.do_create_user(request).await,
            Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
        );
    }

    #[tokio::test]
    async fn test_create_user_wrong_ou() {
        let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
        let request = LdapAddRequest {
            dn: "uid=bob,ou=groups,dc=example,dc=com".to_owned(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Bob".to_vec()],
            }],
        };
        assert_eq!(
            ldap_handler.do_create_user(request).await,
            Err(LdapError{ code: LdapResultCode::InvalidDNSyntax, message: r#"Unexpected DN format. Got "uid=bob,ou=groups,dc=example,dc=com", expected: "uid=id,ou=people,dc=example,dc=com""#.to_string() })
        );
    }

    #[tokio::test]
    async fn test_create_user_multiple_object_class() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_create_user()
            .with(eq(CreateUserRequest {
                user_id: UserId::new("bob"),
                email: "".into(),
                display_name: Some("Bob".to_string()),
                ..Default::default()
            }))
            .times(1)
            .return_once(|_| Ok(()));
        let ldap_handler = setup_bound_admin_handler(mock).await;
        let request = LdapAddRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_owned(),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "cn".to_owned(),
                    vals: vec![b"Bob".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "objectClass".to_owned(),
                    vals: vec![
                        b"top".to_vec(),
                        b"person".to_vec(),
                        b"inetOrgPerson".to_vec(),
                    ],
                },
            ],
        };
        assert_eq!(
            ldap_handler.do_create_user(request).await,
            Ok(vec![make_add_error(LdapResultCode::Success, String::new())])
        );
    }

    #[tokio::test]
    async fn test_search_filter_non_attribute() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(true.into())), eq(false))
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let request = make_user_search_request(
            LdapFilter::Present("displayname".to_owned()),
            vec!["objectClass"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![make_search_success()])
        );
    }

    #[tokio::test]
    async fn test_compare_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|f, g| {
            assert_eq!(f, Some(UserRequestFilter::UserId(UserId::new("bob"))));
            assert!(!g);
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob"),
                    email: "bob@bobmail.bob".into(),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
        // Non-canonical attribute.
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "eMail".to_owned(),
            val: b"bob@bobmail.bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_group() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        mock.expect_list_groups().returning(|f| {
            assert_eq!(f, Some(GroupRequestFilter::DisplayName("group".into())));
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group".into(),
                creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                users: vec![UserId::new("bob")],
                uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                attributes: Vec::new(),
            }])
        });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=group,ou=groups,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"group".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_not_found() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|f, g| {
            assert_eq!(f, Some(UserRequestFilter::UserId(UserId::new("bob"))));
            assert!(!g);
            Ok(vec![])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uid".to_owned(),
            val: b"bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::NoSuchObject,
                matcheddn: "dc=example,dc=com".to_owned(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_no_match() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|f, g| {
            assert_eq!(f, Some(UserRequestFilter::UserId(UserId::new("bob"))));
            assert!(!g);
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("bob"),
                    email: "bob@bobmail.bob".into(),
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups().returning(|_| Ok(vec![]));
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=bob,ou=people,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "mail".to_owned(),
            val: b"bob@bob".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareFalse,
                matcheddn: dn.to_string(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_compare_group_member() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().returning(|_, _| Ok(vec![]));
        mock.expect_list_groups().returning(|f| {
            assert_eq!(f, Some(GroupRequestFilter::DisplayName("group".into())));
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group".into(),
                creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                users: vec![UserId::new("bob")],
                uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                attributes: Vec::new(),
            }])
        });
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let dn = "uid=group,ou=groups,dc=example,dc=com";
        let request = LdapCompareRequest {
            dn: dn.to_string(),
            atype: "uniqueMember".to_owned(),
            val: b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
        };
        assert_eq!(
            ldap_handler.do_compare(request).await,
            Ok(vec![LdapOp::CompareResult(LdapResultOp {
                code: LdapResultCode::CompareTrue,
                matcheddn: dn.to_owned(),
                message: "".to_string(),
                referral: vec![],
            })])
        );
    }

    #[tokio::test]
    async fn test_user_ou_search() {
        let mut ldap_handler = setup_bound_readonly_handler(MockTestBackendHandler::new()).await;
        let request = LdapSearchRequest {
            base: "ou=people,dc=example,dc=com".to_owned(),
            scope: LdapSearchScope::Base,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::And(vec![]),
            attrs: Vec::new(),
        };
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "ou=people,dc=example,dc=com".to_owned(),
                    attributes: vec![LdapPartialAttribute {
                        atype: "objectClass".to_owned(),
                        vals: vec![b"top".to_vec(), b"organizationalUnit".to_vec()]
                    }]
                }),
                make_search_success()
            ])
        );
    }

    #[tokio::test]
    async fn test_custom_attribute_read() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users().times(1).return_once(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("test"),
                    attributes: vec![Attribute {
                        name: "nickname".into(),
                        value: "Bob the Builder".to_string().into(),
                    }],
                    ..Default::default()
                },
                groups: None,
            }])
        });
        mock.expect_list_groups().times(1).return_once(|_| {
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "group".into(),
                creation_date: chrono::Utc.timestamp_opt(42, 42).unwrap().naive_utc(),
                users: vec![UserId::new("bob")],
                uuid: uuid!("04ac75e0-2900-3e21-926c-2f732c26b3fc"),
                attributes: vec![Attribute {
                    name: "club_name".into(),
                    value: "Breakfast Club".to_string().into(),
                }],
            }])
        });
        mock.expect_get_schema().returning(|| {
            Ok(Schema {
                user_attributes: AttributeList {
                    attributes: vec![AttributeSchema {
                        name: "nickname".into(),
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: false,
                        is_readonly: false,
                    }],
                },
                group_attributes: AttributeList {
                    attributes: vec![AttributeSchema {
                        name: "club_name".into(),
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: false,
                        is_readonly: false,
                    }],
                },
                extra_user_object_classes: vec![
                    LdapObjectClass::from("customUserClass"),
                    LdapObjectClass::from("myUserClass"),
                ],
                extra_group_object_classes: vec![LdapObjectClass::from("customGroupClass")],
            })
        });
        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = make_search_request(
            "dc=example,dc=com",
            LdapFilter::And(vec![]),
            vec!["uid", "nickname", "club_name"],
        );
        assert_eq!(
            ldap_handler.do_search_or_dse(&request).await,
            Ok(vec![
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "nickname".to_owned(),
                            vals: vec![b"Bob the Builder".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_owned(),
                            vals: vec![b"test".to_vec()],
                        },
                    ],
                }),
                LdapOp::SearchResultEntry(LdapSearchResultEntry {
                    dn: "cn=group,ou=groups,dc=example,dc=com".to_owned(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "club_name".to_owned(),
                            vals: vec![b"Breakfast Club".to_vec()],
                        },
                        LdapPartialAttribute {
                            atype: "uid".to_owned(),
                            vals: vec![b"group".to_vec()],
                        },
                    ],
                }),
                make_search_success()
            ]),
        );
    }
}
