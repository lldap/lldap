# Configuration for Apache Guacamole
!! IMPORTANT
1. LDAP only works with LLDAP if using a [database authentication](https://guacamole.apache.org/doc/gug/ldap-auth.html#associating-ldap-with-a-database).
2. How to [Guacamole DB Auth](https://guacamole.apache.org/doc/gug/guacamole-docker.html)
3. The Apache Guacamole does support using LDAP to store user config but that is not in scope here.
4. This was achieved by using the docker
5. This guide assumed your already setup DB auth correctly.

##  To setup LDAP [jasonbean/guacamole](https://registry.hub.docker.com/r/jasonbean/guacamole/)

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

* Exclude `ldap-user-search-filter` if you do not want to limit users based on a group(s)
* Replace `dc=example,dc=com` with your LLDAP configured domain for all occurances
* Apache Guacamole does not lock you out when enabling LDAP.  Your `static` IDs still are able to log in.

##  To setup LDAP [guacamole/guacamole](https://hub.docker.com/r/guacamole/guacamole)
Apache Guacamole Official Image already had ENV prepared to pass LDAP config conviniently, passing LDAP parameters and restart guacamole.
Assuming you already working situation with sample of compose snippet here:
```
...
  guacamole:
     image: guacamole/guacamole
     environment:
       - POSTGRES_HOSTNAME=db-hostname
       - POSTGRES_USER=db-username
       - POSTGRES_DATABASE=db-name
       - POSTGRES_PASSWORD=db-pass
       - GUACD_HOSTNAME=guacd-hostname
...
```
Add LDAP environment to compose become:
```
...
  guacamole:
     image: guacamole/guacamole
     environment:
       - POSTGRES_HOSTNAME=db-hostname
       - POSTGRES_USER=db-username
       - POSTGRES_DATABASE=db-name
       - POSTGRES_PASSWORD=db-pass
       - GUACD_HOSTNAME=guacd
       - LDAP_HOSTNAME=ldap-hostname or IP
       - LDAP_PORT=ldap-port
       - LDAP_ENCRYPTION_METHOD=none #disabling SSL
       - LDAP_SEARCH_BIND_DN=uid=admin,ou=people,dc=example,dc=com
       - LDAP_SEARCH_BIND_PASSWORD=replacewithyoursecret
       - LDAP_USER_BASE_DN=ou=people,dc=example,dc=com
       - LDAP_USER_SEARCH_FILTER=(memberof=cn=lldap_apacheguac,ou=groups,dc=example,dc=com)
...
```
References:
For additional parameter can be passed look for `start.sh` link below.
* https://github.com/apache/guacamole-client/blob/master/guacamole-docker/bin/start.sh 

##  To enable LDAP
Restart your Apache Guacamole app for changes to take effect

## To enable users
* Before logging in with an LLDAP user, you have to manually create it using your static ID in Apache Guacamole. This applies to each user that you want to log in with using LDAP authentication, the relation is one to one mean assuming your LDAP login is XYZ then you need create a user XYZ with same name.
* Using static ID use existing connection or create one and assign to created user, otherwise the user will be logged in without any permissions/connections/etc.
* Static ID usually `guacadmin` user and password, except there changes from users.

At last, you can log in with LDAP user, and use connections assigned before.

