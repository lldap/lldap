# Basic LDAP auth for a The Lounge IRC web-client

[Main documentation here.](https://thelounge.chat/docs/configuration#ldap-support)

Simple Config:

```
      ldap: {
        enable: true,
        url: "ldap://localhost:389",
        tlsOptions: {},
        primaryKey: "uid",
        baseDN: "ou=people,dc=example,dc=com",
    },
```

In this config, The Lounge will use the credentials provided in web ui to authenticate with lldap. It'll allow access if authentication was successful and the user is a member of Base DN.


Advanced Config:

```
      ldap: {
        enable: true,
        url: "ldap://localhost:389",
        tlsOptions: {},
        primaryKey: "uid",
        searchDN: {
            rootDN: "uid=ldap-viewer,ou=people,dc=example,dc=com",
            rootPassword: ""
            filter: "(memberOf=cn=thelounge,ou=groups,dc=example,dc=com)",
            base: "dc=example,dc=com",
            scope: "sub",
        },
    },
```

`rootDN` is similar to bind DN in other applications. It is used in combination with `rootPassword` to query lldap. `ldap-viewer` user in `lldap` is a member of the group `lldap_strict_readonly` group. This gives `ldap-viewer` user permission to query `lldap`.



With the `filter`, You can limit The Lounge access to users who are a member of the group `thelounge`.
