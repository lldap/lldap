# Configuration for Jellyfin

Replace `dc=example,dc=com` with your LLDAP configured domain.

### LDAP Bind User
```
uid=admin,ou=people,dc=example,dc=com
```

### LDAP Base DN for searches
```
ou=people,dc=example,dc=com
```

### LDAP Attributes

```
uid, mail
```

### LDAP Name Attribute

```
uid
```

### User Filter

If you have a `media` group, you can use:
```
(memberof=cn=media,ou=groups,dc=example,dc=com)
```

Otherwise, just use:
```
(uid=*)
```
### Admin Base DN

The DN to search for your admins.
```
ou=people,dc=example,dc=com
```

### Admin Filter

Same here. If you have `media_admin` group (doesn't have to be named like
that), use:
```
(memberof=cn=media_admin,ou=groups,dc=example,dc=com)
```
Bear in mind that admins must also be a member of the users group if you use one.

Otherwise, you can use LLDAP's admin group:
```
(memberof=cn=lldap_admin,ou=groups,dc=example,dc=com)
```
