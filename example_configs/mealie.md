# Mealie

Configuration is done solely with environmental variables in the mealie-api docker-compose config:

## Note
[LDAP integration in Mealie currently only works with the nightly branch](https://github.com/hay-kot/mealie/issues/2402#issuecomment-1560176528), so `hkotel/mealie:api-nightly` and `hkotel/mealie:frontend-nightly` rather than the current "stable" release of `v1.0.0beta-5`

## Configuration

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
