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

- [ ] Enable StartTLD

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
- [ ] authentik default Active Directory Mapping: givenName
- [ ] authentik default Active Directory Mapping: sAMAccountName
- [ ] authentik default Active Directory Mapping: sn
- [ ] authentik default Active Directory Mapping: userPrincipalName
- [x] authentik default OpenLDAP Mapping: cn
- [x] authentik default OpenLDAP Mapping: uid

## Group Property Mappings
- [x] authentik default LDAP Mapping:
- [x] authentik default LDAP Mapping:
- [ ] authentik default Active Directory Mapping:
- [ ] authentik default Active Directory Mapping:
- [ ] authentik default Active Directory Mapping:
- [ ] authentik default Active Directory Mapping:
- [x] authentik default OpenLDAP Mapping:
- [x] authentik default OpenLDAP Mapping:

# Additional settings

## Group
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

## Object uniqueness field
```
cn
```
