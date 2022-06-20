# Configuration for Portainer CE
##  Settings > Authentication 
---

## LDAP configuration 
### LDAP Server
```
localhost:3890
```
### Anonymous mode
```
off
```
### Reader DN
```
uid=admin,ou=people,dc=example,dc=com
```
### Password
```
xxx
```


## User search configurations
### Base DN
```
ou=people,dc=example,dc=com
```
### Username attribute
```
uid
```
### Filter (all available user)
```
(objectClass=person)
```
### Filter by groups (assuming you already create and manage the user into group, in this example the user already in lldap_portainer group)
```
(&(objectClass=person)(memberof=cn=lldap_portainer,ou=groups,dc=example,dc=com))
```


## Group search configurations 
### Group Base DN
```
ou=groups,dc=example,dc=com
```
### Group Membership Attribute
```
cn
```
### Group Filter 
```
is optional
```
