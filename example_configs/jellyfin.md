# Configuration for Jellyfin

Replace all instances of `dc=example,dc=com` with your LLDAP configured domain.

## LDAP Server Settings
### LDAP Bind User
Create an ldap user for Jellyfin to run search queries (and optionally reset passwords). For example `jellyfin_bind_user`
```
uid=jellyfin_bind_user,ou=people,dc=example,dc=com
```

### LDAP Base DN for searches
```
ou=people,dc=example,dc=com
```

## LDAP User Settings
### LDAP Search Filter
If you have a `media` group, you can use:
```
(memberof=cn=media,ou=groups,dc=example,dc=com)
```
Otherwise, just use:
```
(uid=*)
```
### LDAP Search Attributes
```
uid, mail
```
### LDAP Uid Attribute
```
uid
```
### LDAP Username Attribute
```
uid
```
### LDAP Password Attribute
```
userPassword
```

### LDAP Admin Base DN
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

## Password change
To allow changing Passwords via Jellyfin the following things are required
- The bind user needs to have the group lldap_password_manager (changing passwords of members of the group lldap_admin does not work to prevent privilege escalation)
- Check `Allow Password Change`
- `LDAP Password Attribute` Needs to be set to `userPassword`
