# Configuration for Apereo CAS Server

Replace `dc=example,dc=com` with your LLDAP configured domain, and hostname for your LLDAP server.

The `search-filter` provided here requires users to be members of the `cas_auth` group in LLDAP.

Configuration to use LDAP in e.g. `/etc/cas/config/standalone.yml`
```
cas:
  authn:
    ldap:
    - base-dn: dc=example,dc=com
      bind-credential: password
      bind-dn: uid=admin,ou=people,dc=example,dc=com
      ldap-url: ldap://ldap.example.com:3890
      search-filter: (&(objectClass=person)(memberOf=uid=cas_auth,ou=groups,dc=example,dc=com))
```

