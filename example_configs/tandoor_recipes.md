LDAP_AUTH=1
AUTH_LDAP_SERVER_URI=ldap://lldap:3890/
AUTH_LDAP_BIND_DN=uid=ro_admin,ou=people,DC=example,DC=com
AUTH_LDAP_BIND_PASSWORD=CHANGEME
AUTH_LDAP_USER_SEARCH_BASE_DN=ou=people,DC=example,DC=com
AUTH_LDAP_USER_SEARCH_FILTER_STR=(&(&(objectclass=person)(memberOf=cn=tandoor_users,ou=groups,dc=example,dc=com))(uid=%(user)s))
AUTH_LDAP_USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn', 'email': 'mail'}
AUTH_LDAP_ALWAYS_UPDATE_USER=1
