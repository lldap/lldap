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
### Filter 
```
(objectClass=person)
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
