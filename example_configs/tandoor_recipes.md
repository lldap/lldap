# Tandoor Recipes LDAP configuration

## LDAP settings are defined by environmental variables as defined in [Tandoor's documentation](https://docs.tandoor.dev/features/authentication/#ldap)

### #Required#
It is recommended to have a read-only account to bind to
```
LDAP_AUTH=1
AUTH_LDAP_SERVER_URI=ldap://lldap:3890/
AUTH_LDAP_BIND_DN=uid=ro_admin,ou=people,DC=example,DC=com
AUTH_LDAP_BIND_PASSWORD=CHANGEME
AUTH_LDAP_USER_SEARCH_BASE_DN=ou=people,DC=example,DC=com
```

### #Optional#

By default it authenticates everybody identified by the search base DN, this allows you to pull certain users from the ```tandoor_users``` group
```
AUTH_LDAP_USER_SEARCH_FILTER_STR=(&(&(objectclass=person)(memberOf=cn=tandoor_users,ou=groups,dc=example,dc=com))(uid=%(user)s))
```

Map Tandoor user fields with their LLDAP counterparts
```
AUTH_LDAP_USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn', 'email': 'mail'}
```

Set whether or not to always update user fields at login and how many seconds for a timeout
```
AUTH_LDAP_ALWAYS_UPDATE_USER=1
AUTH_LDAP_CACHE_TIMEOUT=3600
```

If you use secure LDAP
```
AUTH_LDAP_START_TLS=1
AUTH_LDAP_TLS_CACERTFILE=/etc/ssl/certs/own-ca.pem
```
