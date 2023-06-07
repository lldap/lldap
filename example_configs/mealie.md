# Mealie

Configuration is done solely with environmental variables in the mealie-api docker-compose config:

The following config should get you able to login with either members of the `mealie` group as a user, or as an admin user with members of the `mealie-admin` group.
```yaml
            - LDAP_AUTH_ENABLED=true
            - LDAP_SERVER_URL=ldap://lldap:3890
            - LDAP_TLS_INSECURE=true
            - LDAP_BASE_DN=ou=people,dc=example,dc=com
            - LDAP_USER_FILTER=(memberof=cn=mealie,ou=groups,dc=example,dc=com)
            - LDAP_QUERY_BIND=cn=admin,ou=people,dc=example,dc=com
            - LDAP_QUERY_PASSWORD=ADMINPASSWORD
            - LDAP_ID_ATTRIBUTE=uid
            - LDAP_NAME_ATTRIBUTE=cn
            - LDAP_MAIL_ATTRIBUTE=mail
            - LDAP_ADMIN_FILTER=(memberof=cn=mealie-admin,ou=groups,dc=example,dc=com)
```   
