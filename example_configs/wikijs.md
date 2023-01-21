# Configuration for WikiJS
Replace `dc=example,dc=com` with your LLDAP configured domain.
### LDAP URL
```
ldap://lldap:3890
```
### Admin Bind DN
```
cn=admin,ou=people,dc=example,dc=com
```
or 
```
cn=readonlyuser,ou=people,dc=example,dc=com
```
### Admin Bind Credentials
```
ADMINPASSWORD
```
or
```
READONLYUSERPASSWORD
```
### Search Base
```
ou=people,dc=example,dc=com
```
### Search Filter
If you wish the permitted users to be restricted to just the `wiki` group: 
```
(&(memberof=cn=wiki,ou=groups,dc=example,dc=com)(|(uid={{username}})(mail={{username}))(objectClass=person))
```
If you wish any of the registered LLDAP users to be permitted to use WikiJS:
```
(&(|(uid={{username}})(mail={{username}))(objectClass=person))
```
### Use TLS
Left toggled off
### Verify TLS Certificate
Left toggled off
### TLS Certificate Path
Left blank
### Unique ID Field Mapping
```
uid
```
### Email Field Mapping
```
mail
```
### Display Name Field Mapping
```
givenname
```
### Avatar Picture Field Mapping
```
jpegPhoto
```
### Allow self-registration
Toggled on
### Limit to specific email domains
Left blank
### Assign to group
I created a group called `users` and assign my LDAP users to that by default. 
You can use the local admin account to login and promote an LDAP user to `admin` group if you wish and then deactivate the local login option 
