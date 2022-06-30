# Configuration for Apache Guacamole
!! IMPORTANT - LDAP only works with LLDAP if using a [database authentication](https://guacamole.apache.org/doc/gug/ldap-auth.html#associating-ldap-with-a-database).  The Apache Guacamole does support using LDAP to store user config but that is not in scope here.
This was achieved by using the docker [jasonbean/guacamole](https://registry.hub.docker.com/r/jasonbean/guacamole/).

##  To setup LDAP

### Using `guacamole.properties`
Open and edit your Apache Guacamole properties files

Located at `guacamole/guacamole.properties`

Uncomment and insert the below into your properties file

```
### http://guacamole.apache.org/doc/gug/ldap-auth.html
### LDAP Properties
ldap-hostname: localhost
ldap-port: 3890
ldap-user-base-dn: ou=people,dc=example,dc=com
ldap-username-attribute: uid
ldap-search-bind-dn: uid=admin,ou=people,dc=example,dc=com
ldap-search-bind-password: replacewithyoursecret
ldap-user-search-filter: (memberof=cn=lldap_apacheguac,ou=groups,dc=example,dc=com)
```

### Using docker variables

```
LDAP_HOSTNAME: localhost
LDAP_PORT: 3890
LDAP_ENCRYPTION_METHOD: none
LDAP_USER_BASE_DN: ou=people,dc=example,dc=com
LDAP_USERNAME_ATTRIBUTE: uid
LDAP_SEARCH_BIND_DN: uid=admin,ou=people,dc=example,dc=com
LDAP_SEARCH_BIND_PASSWORD: replacewithyoursecret
LDAP_USER_SEARCH_FILTER: (memberof=cn=lldap_guacamole,ou=groups,dc=example,dc=com) 
```

### Notes
* You set it either through `guacamole.properties` or docker variables, not both.
* Exclude `ldap-user-search-filter/LDAP_USER_SEARCH_FILTER` if you do not want to limit users based on a group(s)
  * it is a filter that permits users with `lldap_guacamole` sample group.
* Replace `dc=example,dc=com` with your LLDAP configured domain for all occurances
* Apache Guacamole does not lock you out when enabling LDAP.  Your `static` IDs still are able to log in.
* setting `LDAP_ENCRYPTION_METHOD` is disabling SSL

##  To enable LDAP
Restart your Apache Guacamole app for changes to take effect

## To enable users
Before logging in with an LLDAP user, you have to manually create it using your static ID in Apache Guacamole. This applies to each user that you want to log in with using LDAP authentication.  Otherwise the user will be logged in without any permissions/connections/etc.

Using your static ID, create a username that matches your target LDAP username. If applicable, tick the permissions and/or connections that you want this user to see.

Log in with LDAP user.

