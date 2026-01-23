# Configuration for Continuwuity

This example is with environment vars from my docker-compose.yml, this also works just as well with a [config file](https://continuwuity.org/reference/config). `uid=query,ou=people,dc=example,dc=com` is a read-only user and you need to put their password into `/etc/bind_password_file`. Users need to be in the group `matrix` to log in and users in the group `matrix-admin` will be an admin.

```
CONTINUWUITY_LDAP__ENABLE: 'true'
CONTINUWUITY_LDAP__LDAP_ONLY: 'true'
CONTINUWUITY_LDAP__URI: 'ldap://lldap.example.com:3890'
CONTINUWUITY_LDAP__BASE_DN: 'ou=people,dc=example,dc=com'
CONTINUWUITY_LDAP__BIND_DN: 'uid=query,ou=people,dc=example,dc=com'
CONTINUWUITY_LDAP__BIND_PASSWORD_FILE: '/etc/bind_password_file'
CONTINUWUITY_LDAP__FILTER: '(memberOf=matrix)'
CONTINUWUITY_LDAP__UID_ATTRIBUTE: 'uid'
CONTINUWUITY_LDAP__ADMIN_FILTER: '(memberOf=matrix-admin)'
```
