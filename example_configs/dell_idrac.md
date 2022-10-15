# Configuration for Dell iDRAC

## iDRAC 9

iDRAC 9 can only be connected to LDAPS, so make sure you have that enabled.

The settings then are as follows:

### Use Distinguished Name to Search Group Membership
```
Enabled
```

### LDAP Server Address
```
Your server address eg. localhost
```

### LDAP Server Port
```
Your LDAPS port, eg. 6360 or 636
```

### Bind DN
```
uid=admin,ou=people,dc=example,dc=com
```

### Bind Password
```
Enabled
```

### Bind Password
```
Your admin user password
```

### Attribute of User Login
```
uid
```

### Attribute of Group Membership
```
member
```

### Search Filter
```
(&(objectClass=person)(memberof=cn=idrac_users,ou=groups,dc=example,dc=com))
```

For the Group Role Mappings, you define groups by their full `Group DN`, eg.
```
cn=idrac_users,ou=groups,dc=example,dc=com
```
