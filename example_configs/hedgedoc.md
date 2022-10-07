# Configuration for hedgedoc

[Hedgedoc](https://hedgedoc.org/) is a platform to write and share markdown.

### Using docker variables

Any member of the group ```hedgedoc``` can log into hedgedoc.
```
- CMD_LDAP_URL=ldap://lldap:3890
- CMD_LDAP_BINDDN=uid=admin,ou=people,dc=example,dc=com
- CMD_LDAP_BINDCREDENTIALS=insert_your_password
- CMD_LDAP_SEARCHBASE=ou=people,dc=example,dc=com
- CMD_LDAP_SEARCHFILTER=(&(memberOf=cn=hedgedoc,ou=groups,dc=example,dc=com)(uid={{username}}))
- CMD_LDAP_USERIDFIELD=uid
```
Replace `dc=example,dc=com` with your LLDAP configured domain for all occurances
