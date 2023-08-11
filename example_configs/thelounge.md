# Basic LDAP auth for a The Lounge IRC web-client

[Main documentation here.](https://thelounge.chat/docs/configuration#ldap-support)

For simple user auth with LLDAP on localhost adapt this in the main config.js:

```
      ldap: {
        enable: true,
        url: "ldap://localhost:389",
        tlsOptions: {},
        primaryKey: "uid",
        // baseDN: "ou=people,dc=example,dc=com",
        searchDN: {
            rootDN: "uid=ldap-editor,ou=people,dc=example,dc=com",
            rootPassword: ""
            filter: "(memberOf=cn=thelounge,ou=groups,dc=example,dc=com)",
            base: "dc=example,dc=com",
            scope: "sub",
        },
    },
```

`rootDN` is similar to bind DN in other applications. It is used in combination with `rootPassword` to query lldap. `ldap-editor` user in `lldap` is a member of `lldap_password_manager` and `lldap_strict_readonly` groups. This gives `ldap-editor` user permission to query `lldap` and the permission to change passwords.

For simpler setups, There is an optional `baseDN` field as well. If `baseDN` is configured, It'll look up `lldap` after logging in with the credentials provided by the user to the lounge.
