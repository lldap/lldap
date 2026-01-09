# Configuration for Gerrit

Edit `gerrit.config`:
```ini
[auth]
  type = ldap

[ldap]
  server = ldap://lldap:3890
  supportAnonymous = false
  username = uid=gerritadmin,ou=people,dc=example.com,dc=com
  accountBase = ou=people,dc=example.com,dc=com
  accountPattern = (uid=${username})
  accountFullName = cn
  accountEmailAddress = mail
```

The `supportAnonymous = false` must be set.