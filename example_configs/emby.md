# Configuration for Emby

Emby only uses LDAP to create users and validate passwords upon login. Emby administrators are always validated via native emby login.
https://emby.media/introducing-ldap-support-for-emby.html

Replace `dc=example,dc=com` with your LLDAP configured domain.

### Bind DN
```
cn=admin,ou=people,dc=example,dc=com
```

### Bind Credentials
```
changeme (replace with your password)
```

### User search base
```
ou=people,dc=example,dc=com
```

### User search filter

replace the `emby_user` cn with the group name for accounts that should be able to login to Emby, otherwise leave the default `(uid={0})`.

```
(&(uid={0})(memberOf=cn=emby_user,ou=groups,dc=example,dc=com))
```
