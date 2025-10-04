# Configuration for Portainer CE/BE
###  Settings > Authentication > LDAP > Custom
---

## LDAP configuration

#### LDAP Server
```
localhost:3890 or ip-address:3890
```
#### Anonymous mode
```
off
```
#### Reader DN
```
uid=admin,ou=people,dc=example,dc=com
```
#### Password
```
xxx
```
* Password is the ENV you set at *LLDAP_LDAP_USER_PASS=* or `lldap_config.toml`

## User search configurations

#### Base DN
```
ou=people,dc=example,dc=com
```
#### Username attribute
```
uid
```
### Filter
#### All available user(s)
```
(objectClass=person)
```
* Using this filter will list all user registered in LLDAP

#### All user(s) from specific group
```
(&(objectClass=person)(memberof=cn=lldap_portainer,ou=groups,dc=example,dc=com))
```
* Using this filter will only list user that included in `lldap_portainer` group. 
* Admin should manually configure groups and add a user to it. **lldap_portainer** only sample.



## Group search configurations 

#### Group Base DN
```
ou=groups,dc=example,dc=com
```
#### Group Membership Attribute
```
uniqueMember
```
#### Group Filter 
Is optional:
```
(objectClass=groupofuniquenames)
```

## Admin group search configurations 

Use the same configurations as above to grant each users admin rights in their respective teams.
You can then also fetch all groups, and select which groups have universal admin rights.
