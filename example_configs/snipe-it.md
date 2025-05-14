### Configuration for Snipe-IT

1. Navigate to `/admin/ldap`
2. Check the "LDAP enabled" checkbox
3. In the "LDAP Server" field, enter `ldap://lldap:3890`
4. In the "LDAP Bind Username" field, enter `uid=admin,ou=people,dc=example,dc=com`. Replace `admin` with the bind user you use.
5. In the "LDAP Bind Password" field, enter your bind user's password
6. In the "Base Bind DN" field, enter `ou=people,dc=example,dc=com`
7. In the "LDAP filter" field, you can enter `&(memberof=cn=snipeit,ou=groups,dc=example,dc=com)` to only allow users in group `snipeit` to login. The group must be created and users assigned to it for this to work.
8. The "Username Field" value should be `uid`
9. The "Last name" value should be `sn`
10. The "LDAP First Name" value should be `givenname`
11. The "LDAP Authentication query" should be `uid=`
12. Optional: If you require email, the "LDAP Email" value should be set to `mail`
13. Optional: By default, users in Snipe-IT have almost no privileges. You can assign privileges for LLDAP users by setting a "Default Permissions Group", which requires you to [create a group](https://snipe-it.readme.io/docs/groups) beforehand.

