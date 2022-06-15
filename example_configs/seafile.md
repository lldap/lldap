# Configuration for Seafile

## Basic configuration
Add the following to your `seafile/conf/ccnet.conf` file:
```
[LDAP]
HOST = ldap://192.168.1.100:3890
BASE = ou=people,dc=example,dc=com
USER_DN = uid=admin,ou=people,dc=example,dc=com
PASSWORD = CHANGE_ME
LOGIN_ATTR = mail
```
* Replace `192.168.1.100:3890` with your lldap server's ip/hostname and port.
* Replace every instance of `dc=example,dc=com` with your configured domain.

__IMPORTANT__: Seafile requires the LOGIN_ATTR to be in an email-like format. You cannot use the uid as LOGIN_ATTR!

After restarting the Seafile server, users should be able to log in with their email address and password.

## Filtering by group membership
If you only want members of a specific group to be able to log in, add the following line:
```
FILTER = memberOf=cn=seafile_user,ou=groups,dc=example,dc=com
```
* Replace `seafile_user` with the name of your group.
