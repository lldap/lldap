# Configuration for Jenkins

## Jenkins base setup

To setup LLDAP for Jenkins navigate to Dashboard/Manage Jenkins/Security. 

*Note: Jenkins LDAP plugin has to be installed!</br>*
*Note: "dc=example,dc=com" is default configuration, you should replace it with your base DN.*

1) Set **Security Realm** to **LDAP**
2) Click Add Server
3) Setup config fields as stated below

## Config fields

#### Server
*(This can be replaced by server ip/your domain etc.)*
```
ldap://example.com:3890
```
### Advanced Server Configuration Dropdown

#### root DN
```
dc=example,dc=com
```

#### Allow blank rootDN
```
true
```

#### User search base
```
ou=people
```

#### User search filter
```
uid={0}
```

#### Group search base
```
ou=groups
```

#### Group search filter
```
(& (cn={0})(objectclass=groupOfNames))
```

#### Group membership
Select Search for LDAP groups containing user and leave Group membership filter empty

#### Manager DN
Leave here your admin account
```
cn=admin,ou=people
```
#### Manager Password
Leave it as is

#### Display Name LDAP attribute
Leave cn as it inputs username
```
cn
```

#### Email Address LDAP attribute
```
mail
```

### Tips & Tricks
- Always use Test LDAP settings so you won't get locked out. It works without password.
- If you want to setup your permissions, go to Authorization setting and select Matrix-based security. Add group/user (it has to exist in LLDAP) and you can grant him permissions. Note that Overall Read forbids users to read jenkins and execute actions. Administer gives full rights.

### Useful links:
https://plugins.jenkins.io/ldap/</br>
https://www.jenkins.io/doc/book/security/managing-security/
