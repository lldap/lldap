use crate::core::{
    error::{LdapError, LdapResult},
    group::{convert_groups_to_ldap_op, get_groups_list},
    user::{convert_users_to_ldap_op, get_user_list},
    utils::{LdapInfo, LdapSchemaDescription, is_subtree, parse_distinguished_name},
};
use chrono::Utc;
use ldap3_proto::{
    LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry, LdapSearchScope,
    proto::{
        LdapDerefAliases, LdapOp, LdapResult as LdapResultOp, LdapSearchRequest,
        OID_PASSWORD_MODIFY, OID_WHOAMI,
    },
};
use lldap_access_control::UserAndGroupListerBackendHandler;
use lldap_domain::{
    public_schema::PublicSchema,
    types::{Group, UserAndGroups},
};
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

pub(crate) fn make_search_request<S: Into<String>>(
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

pub(crate) fn make_search_success() -> LdapOp {
    make_search_error(LdapResultCode::Success, "".to_string())
}

pub(crate) fn make_search_error(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::SearchResultDone(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

pub(crate) fn root_dse_response(base_dn: &str) -> LdapOp {
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
                vals: vec![
                    concat!("lldap_", env!("CARGO_PKG_VERSION"))
                        .to_string()
                        .into_bytes(),
                ],
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

pub fn make_ldap_subschema_entry(schema: PublicSchema) -> LdapOp {
    let ldap_schema_description: LdapSchemaDescription = LdapSchemaDescription::from(schema);
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
            vals: {
                let hardcoded_attributes = [
                    b"( 2.0 NAME 'String' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".to_vec(),
                    b"( 2.1 NAME 'Integer' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )".to_vec(),
                    b"( 2.2 NAME 'JpegPhoto' SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )".to_vec(),
                    b"( 2.3 NAME 'DateTime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".to_vec(),
                ];
                let num_hardcoded_attributes = hardcoded_attributes.len();
                hardcoded_attributes.into_iter().chain(
                    ldap_schema_description
                        .formatted_attribute_list(num_hardcoded_attributes)
                ).collect()
            }
           },
           LdapPartialAttribute {
            atype: "objectClasses".to_string(),
            vals: vec![
                    format!(
                        "( 3.0 NAME ( {} ) DESC 'LLDAP builtin: a person' STRUCTURAL MUST ( {} ) MAY ( {} ) )",
                        ldap_schema_description.user_object_classes().format_for_ldap_schema_description(),
                        ldap_schema_description.required_user_attributes().format_for_ldap_schema_description(),
                        ldap_schema_description.optional_user_attributes().format_for_ldap_schema_description(),
                    ).into_bytes(),
                    format!(
                        "( 3.1 NAME ( {} ) DESC 'LLDAP builtin: a group' STRUCTURAL MUST ( {} ) MAY ( {} ) )",
                        ldap_schema_description.group_object_classes().format_for_ldap_schema_description(),
                        ldap_schema_description.required_group_attributes().format_for_ldap_schema_description(),
                        ldap_schema_description.optional_group_attributes().format_for_ldap_schema_description(),
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

pub(crate) fn is_root_dse_request(request: &LdapSearchRequest) -> bool {
    if request.base.is_empty() && request.scope == LdapSearchScope::Base {
        if let LdapFilter::Present(attribute) = &request.filter {
            if attribute.eq_ignore_ascii_case("objectclass") {
                return true;
            }
        }
    }
    false
}

pub(crate) fn is_subschema_entry_request(request: &LdapSearchRequest) -> bool {
    request.base == "cn=Subschema" && request.scope == LdapSearchScope::Base
}

async fn do_search_internal(
    ldap_info: &LdapInfo,
    backend_handler: &impl UserAndGroupListerBackendHandler,
    request: &LdapSearchRequest,
    schema: &PublicSchema,
) -> LdapResult<InternalSearchResults> {
    let dn_parts = parse_distinguished_name(&request.base.to_ascii_lowercase())?;
    let scope = get_search_scope(&ldap_info.base_dn, &dn_parts, &request.scope);
    debug!(?request.base, ?scope);
    // Disambiguate the lifetimes.
    fn cast<'a, T, R>(x: T) -> T
    where
        T: Fn(&'a LdapFilter) -> R + 'a,
    {
        x
    }

    let get_user_list = cast(async |filter: &LdapFilter| {
        let need_groups = request
            .attrs
            .iter()
            .any(|s| s.eq_ignore_ascii_case("memberof"));
        get_user_list(
            ldap_info,
            filter,
            need_groups,
            &request.base,
            backend_handler,
            schema,
        )
        .await
    });
    let get_group_list = cast(|filter: &LdapFilter| async {
        get_groups_list(ldap_info, filter, &request.base, backend_handler, schema).await
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
                (Err(user_error), Err(_)) => InternalSearchResults::Raw(vec![make_search_error(
                    user_error.code,
                    user_error.message,
                )]),
                (Ok(users), Ok(groups)) => InternalSearchResults::UsersAndGroups(users, groups),
            }
        }
        SearchScope::Users => {
            InternalSearchResults::UsersAndGroups(get_user_list(&request.filter).await?, Vec::new())
        }
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
                &request.base, &ldap_info.base_dn_str, &ldap_info.base_dn_str
            );
            InternalSearchResults::Empty
        }
        SearchScope::Invalid => {
            // Search path is not in our tree, just return an empty success.
            warn!(
                "The specified search tree {:?} is not under the common subtree {:?}",
                &dn_parts, &ldap_info.base_dn
            );
            InternalSearchResults::Empty
        }
    })
}

#[instrument(skip_all, level = "debug")]
pub async fn do_search(
    backend_handler: &impl UserAndGroupListerBackendHandler,
    ldap_info: &LdapInfo,
    request: &LdapSearchRequest,
) -> LdapResult<Vec<LdapOp>> {
    let schema = PublicSchema::from(backend_handler.get_schema().await.map_err(|e| LdapError {
        code: LdapResultCode::OperationsError,
        message: format!("Unable to get schema: {:#}", e),
    })?);
    let search_results = do_search_internal(ldap_info, backend_handler, request, &schema).await?;
    let mut results = match search_results {
        InternalSearchResults::UsersAndGroups(users, groups) => {
            convert_users_to_ldap_op(users, &request.attrs, ldap_info, &schema)
                .chain(convert_groups_to_ldap_op(
                    groups,
                    &request.attrs,
                    ldap_info,
                    backend_handler.user_filter(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::error::LdapError,
        handler::tests::{
            make_group_search_request, make_user_search_request, setup_bound_admin_handler,
            setup_bound_handler_with_group, setup_bound_readonly_handler,
        },
    };
    use chrono::{DateTime, Duration, NaiveDateTime, TimeZone};
    use ldap3_proto::proto::{LdapDerefAliases, LdapSearchScope, LdapSubstringFilter};
    use lldap_domain::{
        schema::{AttributeList, AttributeSchema, Schema},
        types::{
            Attribute, AttributeName, AttributeType, GroupDetails, GroupId, JpegPhoto,
            LdapObjectClass, User, UserId,
        },
        uuid,
    };
    use lldap_domain_handlers::handler::*;
    use lldap_domain_model::model::UserColumn;
    use lldap_test_utils::MockTestBackendHandler;
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_search_root_dse() {
        let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
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

    fn assert_timestamp_within_margin(
        timestamp_bytes: &[u8],
        base_timestamp_dt: DateTime<Utc>,
        time_margin: Duration,
    ) {
        let timestamp_str =
            std::str::from_utf8(timestamp_bytes).expect("Invalid conversion from UTF-8 to string");
        let timestamp_naive = NaiveDateTime::parse_from_str(timestamp_str, "%Y%m%d%H%M%SZ")
            .expect("Invalid timestamp format");
        let timestamp_dt: DateTime<Utc> = Utc.from_utc_datetime(&timestamp_naive);

        let within_range = (base_timestamp_dt - timestamp_dt).abs() <= time_margin;

        assert!(
            within_range,
            "Timestamp not within range: expected within [{} - {}], got [{}]",
            base_timestamp_dt - time_margin,
            base_timestamp_dt + time_margin,
            timestamp_dt
        );
    }

    #[tokio::test]
    async fn test_subschema_response() {
        let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;

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

        let actual_reponse: Vec<LdapOp> = ldap_handler.do_search_or_dse(&request).await.unwrap();

        let LdapOp::SearchResultEntry(search_result_entry) = &actual_reponse[0] else {
            panic!("Expected SearchResultEntry");
        };

        let attrs = &search_result_entry.attributes;
        assert_eq!(attrs.len(), 9);
        assert_eq!(search_result_entry.dn, "cn=Subschema".to_owned());

        assert_eq!(
            attrs[0],
            LdapPartialAttribute {
                atype: "structuralObjectClass".to_owned(),
                vals: vec![b"subentry".to_vec()]
            }
        );

        assert_eq!(
            attrs[1],
            LdapPartialAttribute {
                atype: "objectClass".to_owned(),
                vals: vec![
                    b"top".to_vec(),
                    b"subentry".to_vec(),
                    b"subschema".to_vec(),
                    b"extensibleObject".to_vec()
                ]
            }
        );

        assert_eq!(
            attrs[2],
            LdapPartialAttribute {
                atype: "cn".to_owned(),
                vals: vec![b"Subschema".to_vec()]
            }
        );

        let check_timestamp_attribute = |attr: &LdapPartialAttribute, expected_type: &str| {
            assert_eq!(attr.atype, expected_type);
            assert_eq!(attr.vals.len(), 1);
            assert_timestamp_within_margin(&attr.vals[0], Utc::now(), Duration::seconds(300));
        };
        check_timestamp_attribute(&attrs[3], "createTimestamp");
        check_timestamp_attribute(&attrs[4], "modifyTimestamp");

        assert_eq!(
            attrs[5],
            LdapPartialAttribute {
                atype: "ldapSyntaxes".to_owned(),
                vals: vec![
                    b"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' X-NOT-HUMAN-READABLE 'TRUE' )"
                        .to_vec()
                ]
            }
        );

        assert_eq!(
            attrs[6],
            LdapPartialAttribute {
                atype: "attributeTypes".to_owned(),
                vals: vec![
                    b"( 2.0 NAME 'String' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".to_vec(),
                    b"( 2.1 NAME 'Integer' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )".to_vec(),
                    b"( 2.2 NAME 'JpegPhoto' SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )".to_vec(),
                    b"( 2.3 NAME 'DateTime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".to_vec(),
                    b"( 2.4 NAME 'avatar' DESC 'LLDAP: builtin attribute' SUP JpegPhoto )".to_vec(),
                    b"( 2.5 NAME 'creation_date' DESC 'LLDAP: builtin attribute' SUP DateTime )"
                        .to_vec(),
                    b"( 2.6 NAME 'display_name' DESC 'LLDAP: builtin attribute' SUP String )"
                        .to_vec(),
                    b"( 2.7 NAME 'first_name' DESC 'LLDAP: builtin attribute' SUP String )"
                        .to_vec(),
                    b"( 2.8 NAME 'last_name' DESC 'LLDAP: builtin attribute' SUP String )".to_vec(),
                    b"( 2.9 NAME 'mail' DESC 'LLDAP: builtin attribute' SUP String )".to_vec(),
                    b"( 2.10 NAME 'user_id' DESC 'LLDAP: builtin attribute' SUP String )".to_vec(),
                    b"( 2.11 NAME 'uuid' DESC 'LLDAP: builtin attribute' SUP String )".to_vec(),
                    b"( 2.12 NAME 'creation_date' DESC 'LLDAP: builtin attribute' SUP DateTime )"
                        .to_vec(),
                    b"( 2.13 NAME 'display_name' DESC 'LLDAP: builtin attribute' SUP String )"
                        .to_vec(),
                    b"( 2.14 NAME 'group_id' DESC 'LLDAP: builtin attribute' SUP Integer )"
                        .to_vec(),
                    b"( 2.15 NAME 'uuid' DESC 'LLDAP: builtin attribute' SUP String )".to_vec()
                ]
            }
        );

        assert_eq!(attrs[7],
            LdapPartialAttribute {
                atype: "objectClasses".to_owned(),
                vals: vec![
                    b"( 3.0 NAME ( 'inetOrgPerson' 'posixAccount' 'mailAccount' 'person' 'customUserClass' ) DESC 'LLDAP builtin: a person' STRUCTURAL MUST ( mail $ user_id ) MAY ( avatar $ creation_date $ display_name $ first_name $ last_name $ uuid ) )".to_vec(),
                    b"( 3.1 NAME ( 'groupOfUniqueNames' 'groupOfNames' ) DESC 'LLDAP builtin: a group' STRUCTURAL MUST ( display_name ) MAY ( creation_date $ group_id $ uuid ) )".to_vec(),
                ]
            }
        );

        assert_eq!(
            attrs[8],
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_owned(),
                vals: vec![b"cn=Subschema".to_vec()]
            }
        );

        assert_eq!(actual_reponse[1], make_search_success());
    }

    #[tokio::test]
    async fn test_search_regular_user() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(
                eq(Some(UserRequestFilter::And(vec![
                    UserRequestFilter::And(Vec::new()),
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
        let ldap_handler = setup_bound_handler_with_group(mock, "regular").await;

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
            .with(eq(Some(UserRequestFilter::And(Vec::new()))), eq(false))
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let ldap_handler = setup_bound_readonly_handler(mock).await;

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
            .with(eq(Some(UserRequestFilter::And(Vec::new()))), eq(true))
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
        let ldap_handler = setup_bound_readonly_handler(mock).await;

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
                    UserRequestFilter::And(Vec::new()),
                    UserRequestFilter::UserId(UserId::new("bob")),
                ]))),
                eq(false),
            )
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let ldap_handler = setup_bound_readonly_handler(mock).await;

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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
            .with(eq(Some(GroupRequestFilter::And(Vec::new()))))
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
                            vals: vec![b"groupOfUniqueNames".to_vec(), b"groupOfNames".to_vec(),],
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
                            vals: vec![b"groupOfUniqueNames".to_vec(), b"groupOfNames".to_vec(),],
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
                GroupRequestFilter::And(Vec::new()),
                GroupRequestFilter::DisplayName("rockstars".into()),
            ]))))
            .times(1)
            .return_once(|_| Ok(vec![]));
        let ldap_handler = setup_bound_readonly_handler(mock).await;

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
        let ldap_handler = setup_bound_readonly_handler(MockTestBackendHandler::new()).await;
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
        let ldap_handler = setup_bound_readonly_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
            .with(eq(Some(GroupRequestFilter::And(Vec::new()))))
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
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
                            vals: vec![b"groupOfUniqueNames".to_vec(), b"groupOfNames".to_vec(),],
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
            .with(eq(Some(GroupRequestFilter::And(Vec::new()))))
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
        let ldap_handler = setup_bound_admin_handler(mock).await;

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
                        vals: vec![
                            chrono::Utc
                                .timestamp_opt(0, 0)
                                .unwrap()
                                .to_rfc3339()
                                .into_bytes(),
                        ],
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
                        vals: vec![b"groupOfUniqueNames".to_vec(), b"groupOfNames".to_vec()],
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
        let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
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
        let ldap_handler = setup_bound_admin_handler(MockTestBackendHandler::new()).await;
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
    async fn test_search_filter_non_attribute() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_users()
            .with(eq(Some(true.into())), eq(false))
            .times(1)
            .return_once(|_, _| Ok(vec![]));
        let ldap_handler = setup_bound_admin_handler(mock).await;
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
    async fn test_user_ou_search() {
        let ldap_handler = setup_bound_readonly_handler(MockTestBackendHandler::new()).await;
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
        let ldap_handler = setup_bound_readonly_handler(mock).await;

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
