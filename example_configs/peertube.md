# Example config for Peertube
## LDAP server settings
### Auth weight
```
100
```
### URL
Enter URL or IP of your LLDAP server, starting with `ldap://` or `ldaps://` if you're using a secure protocol. Then specify port your LLDAP server uses.

Example:
```
ldap://127.0.0.1:3890
```
Toggle `Insecure TLS` if you're using insecure LDAP protocol, or keep untoggled if you're using LDAPS.

### Path to LDAP Server Certificate Chain of Trust
Leave it blank if you're using insecure protol.

## Bind user settings
### Bind DN
```
uid=admin,ou=people,dc=example,dc=com
```
You can create special bind user, but it should belong to group `lldap_admin` or `lldap_strict_readonly`.

### Bind Password
Enter password for bind user you specified on previous step.

## User search settings
### Search base
```
ou=people,dc=example,dc=com
```

### Search filter
```
(|(mail={{username}})(uid={{username}}))
```

### Mail property
```
mail
```

### Mail property index
```
0
```

### Username property
```
uid
```

## Groups settings
The following settings are mandatory.
### Group base
```
ou=groups,dc=example,dc=com
```

### Group filter
```
(member={{dn}})
```

### Administrator group DN
```
cn=peertube_admins,ou=groups,dc=raft-server,dc=local
```
All users who belong to this group will be logged in with `Administrator` role.

### Moderator group DN
```
cn=peertube_moderators,ou=groups,dc=raft-server,dc=local
```
All users who belong to this group will be logged in with `Moderator` role.

### User group DN
```
cn=peertube users,ou=groups,dc=raft-server,dc=local
```
All users who belong to this group will be logged in with `User` role.

### No group matched login
Toggle this box, so users who don't belong to any group specified in previous steps will be logged in with `User` role. Keep this box toggled off so users who don't belong any group specified in previous steps will be refused from logging in.
