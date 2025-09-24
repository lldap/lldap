# Name
```
lldap
```

# Slug
```
lldap
```
- [x] Enabled
- [x] Sync Users
- [x] User password writeback
- [x] Sync groups

# Connection settings

## Server URI
```
ldap://lldap:3890
```

- [ ] Enable StartTLS

## TLS Verification Certificate
```
---------
```

## Bind CN
```
uid=admin,ou=people,dc=example,dc=com
```

## Bind Password
```
ADMIN_PASSWORD
```

## Base DN
```
dc=example,dc=com
```

# LDAP Attribute mapping
## User Property Mappings 
- [x] authentik default LDAP Mapping: mail
- [x] authentik default LDAP Mapping: Name
- [x] authentik default Active Directory Mapping: givenName
- [ ] authentik default Active Directory Mapping: sAMAccountName
- [x] authentik default Active Directory Mapping: sn
- [ ] authentik default Active Directory Mapping: userPrincipalName
- [x] authentik default OpenLDAP Mapping: cn
- [x] authentik default OpenLDAP Mapping: uid

## Group Property Mappings
- [ ] authentik default LDAP Mapping: mail
- [ ] authentik default LDAP Mapping: Name
- [ ] authentik default Active Directory Mapping: givenName
- [ ] authentik default Active Directory Mapping: sAMAccountName
- [ ] authentik default Active Directory Mapping: sn
- [ ] authentik default Active Directory Mapping: userPrincipalName
- [x] authentik default OpenLDAP Mapping: cn
- [ ] authentik default OpenLDAP Mapping: uid

# Additional settings

## Parent Group
```
---------
```

## User path
```
LDAP/users
```

## Addition User DN
```
ou=people
```

## Addition Group DN
```
ou=groups
```

## User object filter
```
(objectClass=person)
```

## Group object filter
```
(objectClass=groupOfUniqueNames)
```

## Group membership field
```
member
```

## User membership attribute
```
distinguishedName
```

## Looking using user attribute
```
false
```

## Object uniqueness field
```
uid
```
