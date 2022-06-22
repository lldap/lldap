!! IMPORTANT - LDAP only works with LLDAP if using a [database authentication](https://guacamole.apache.org/doc/gug/ldap-auth.html#associating-ldap-with-a-database).  The Apache Guacamole does support using LDAP to store user config but that is not in scope here.
This was achieved by using the docker [jasonbean/guacamole](https://registry.hub.docker.com/r/jasonbean/guacamole/).

# Configuration for Apache Guacamole
##  To setup LDAP

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

*Exclude `ldap-user-search-filter` if you do not want to limit users based on a group(s)

*Replace `dc=example,dc=com` with your LLDAP configured domain for all occurances

*Apache Guacamole does not lock you out when enabling LDAP.  Your `static` IDs still are able to log in.

##  To enable LDAP
Restart your Apache Guacamole app for changes to take effect

## To enable users
Before logging in, you have to manually create users in the Apache Guacamole application in order for permissions/connections/etc for the users to be set.

Using your static ID, create a username that matches your LDAP user. If applicable, tick the permissions and/or connections that you want this user to see.

Log in with LDAP user.

