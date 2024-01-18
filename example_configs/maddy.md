# Configuration for Maddy Mail Server

Documentation for maddy LDAP can be found [here](https://maddy.email/reference/auth/ldap/).  
Maddy will automatically create an imap-acct if a new user connects via LDAP.  
Replace `dc=example,dc=com` with your LLDAP configured domain.


## Simple Setup
Depending on the mail client(s) the simple setup can work for you. However, if this does not work for you, follow the instructions in the `Advanced Setup` section.

### DN Template
You only have to specify the dn template:
```
dn_template "cn={username},ou=people,dc=example,dc=com"
```

### Config Example with Docker
Example maddy configuration with LLDAP running in docker.  
You can replace `local_authdb` with another name if you want to use multiple auth backends.  
If you only want to use one storage backend make sure to disable `auth.pass_table local_authdb` in your config if it is still active.
```
auth.ldap local_authdb {
    urls ldap://lldap:3890

    dn_template "cn={username},ou=people,dc=example,dc=com"

    starttls off
    debug off
    connect_timeout 1m
}
```


## Advanced Setup
If the simple setup does not work for you, you can use a proper lookup.

### Bind Credentials
If you have a service account in LLDAP with restricted rights (e.g. `lldap_strict_readonly`), replace `admin` with your LLDAP service account.  
Replace `admin_password` with the password of either the admin or service account.  
```
bind plain "cn=admin,ou=people,dc=example,dc=com" "admin_password"
```
If you do not want to use plain auth check the [maddy LDAP page](https://maddy.email/reference/auth/ldap/) for other options.

### Base DN
```
base_dn "dc=example,dc=com"
```

### Filter
Depending on the mail client, maddy receives and sends either the username or the full E-Mail address as username (even if the username is not an E-Mail).  
For the username use:
```
filter "(&(objectClass=person)(uid={username}))"
```
For mapping the username (as E-Mail):
```
filter "(&(objectClass=person)(mail={username}))"
```
For allowing both, username and username as E-Mail use:
```
filter "(&(|(uid={username})(mail={username}))(objectClass=person))"
```

### Config Example with Docker
Example maddy configuration with LLDAP running in docker.  
You can replace `local_authdb` with another name if you want to use multiple auth backends.  
If you only want to use one storage backend make sure to disable `auth.pass_table local_authdb` in your config if it is still active.
```
auth.ldap local_authdb {
    urls ldap://lldap:3890

    bind plain "cn=admin,ou=people,dc=example,dc=com" "admin_password"
    base_dn "dc=example,dc=com"
    filter "(&(|(uid={username})(mail={username}))(objectClass=person))"

    starttls off
    debug off
    connect_timeout 1m
}
```


