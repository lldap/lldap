# Basic LDAP auth for a The Lounge IRC web-client

[Main documentation here.](https://thelounge.chat/docs/configuration#ldap-support)

For simple user auth with LLDAP on localhost adapt this in the main config.js:

```
      ldap: {
        enable: true,
        url: "ldap://localhost:389",
        tlsOptions: {},
        primaryKey: "uid",
        searchDN: {
            rootDN: "uid=ldap-editor,ou=people,DC=example,DC=com",
            rootPassword: ""
            filter: "(memberOf=CN=thelounge,OU=groups,dc=example,dc=com)",
            base: "dc=example,dc=com",
            scope: "sub",
        },
    },
```

There is the `bindDN` field as well. You can use that if you want a relatively simple setup that does not enforce access control with LDAP groups.
