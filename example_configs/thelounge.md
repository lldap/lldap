# Basic LDAP auth for a The Lounge IRC web-client

[Main documentation here.](https://thelounge.chat/docs/configuration#ldap-support)

For simple user auth with LLDAP on localhost adapt this in the main config.js:

```
ldap: {
  enable: true,
  url: "ldap://127.0.0.1:3890",
  tlsOptions: {},
  primaryKey: "uid",
  baseDN : "ou=people,dc=example,dc=com",
```

And comment out with ```//``` the entire ```searchDN``` block.
