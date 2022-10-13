# Configuration for WeKan

WeKan provides quite sophisticated LDAP authentication.

Their wiki page is here: https://github.com/wekan/wekan/wiki/LDAP

Their Docker Compose file with all possible LDAP configuration values and their explanation is here: https://github.com/wekan/wekan/blob/master/docker-compose.yml

## Docker Sample Settings
Here is a working example for an LDAP confiuration via Docker Compose Environment variables:
```
    environment:
      # Other values for your WeKan installation
      - ...
      # LDAP Section
      - DEFAULT_AUTHENTICATION_METHOD=ldap
      - LDAP_ENABLE=true
      - LDAP_PORT=3890
      - LDAP_HOST=localhost
      - LDAP_USER_AUTHENTICATION=true
      - LDAP_USER_AUTHENTICATION_FIELD=uid
      - LDAP_BASEDN=ou=people,dc=example,dc=com
      - LDAP_RECONNECT=true
      - LDAP_AUTHENTIFICATION=true
      - LDAP_AUTHENTIFICATION_USERDN=uid=admin,ou=people,dc=example,dc=com
      - LDAP_AUTHENTIFICATION_PASSWORD=replacewithyoursecret
      - LDAP_LOG_ENABLED=true
      # If using LDAPS: LDAP_ENCRYPTION=ssl
      - LDAP_ENCRYPTION=false
      # The certification for the LDAPS server. Certificate needs to be included in this docker-compose.yml file.
      #- LDAP_CA_CERT=-----BEGIN CERTIFICATE-----MIIE+G2FIdAgIC...-----END CERTIFICATE-----
      # Use this if you want to limit to a specific group
      - LDAP_USER_SEARCH_FILTER=(&(objectClass=person)(memberof=cn=wekan_users,ou=groups,dc=example,dc=com))
      - LDAP_USER_SEARCH_SCOPE=one
      - LDAP_USER_SEARCH_FIELD=uid
      - LDAP_USERNAME_FIELD=uid
      - LDAP_FULLNAME_FIELD=cn
      - LDAP_EMAIL_FIELD=mail
```
