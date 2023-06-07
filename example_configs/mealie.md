# Mealie

Configuration is done solely with environmental variables in the mealie-api docker-compose config:

## Note
[LDAP integration in Mealie currently only works with the nightly branch](https://github.com/hay-kot/mealie/issues/2402#issuecomment-1560176528), so `hkotel/mealie:api-nightly` and `hkotel/mealie:frontend-nightly` rather than the current "stable" release of `v1.0.0beta-5`

## Configuration

The following config should let you login with either members of the `mealie` group as a user, or as an admin user with members of the `mealie-admin` group.  

Mealie first checks credentials in the `mealie` group to authenticate, then checks for the presence of the user in the `mealie-admin` group and elevates that account to admin status if present, therefore for any account to be an admin account it must belong in both the `mealie` group and the `mealie-admin` group.

```yaml
            - LDAP_AUTH_ENABLED=true
            - LDAP_SERVER_URL=ldap://lldap:3890
            - LDAP_TLS_INSECURE=true ## Only required for LDAPS with a self-signed certificate
            - LDAP_BASE_DN=ou=people,dc=example,dc=com
            - LDAP_USER_FILTER=(memberof=cn=mealie,ou=groups,dc=example,dc=com)
            - LDAP_ADMIN_FILTER=(memberof=cn=mealie-admin,ou=groups,dc=example,dc=com)
            - LDAP_QUERY_BIND=cn=lldap_strict_readonly,ou=people,dc=example,dc=com
            - LDAP_QUERY_PASSWORD=LLDAP_STRICT_READONLY_PASSWORD
            - LDAP_ID_ATTRIBUTE=uid
            - LDAP_NAME_ATTRIBUTE=displayName
            - LDAP_MAIL_ATTRIBUTE=mail
```   
