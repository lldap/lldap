# Basic LDAP auth for an Ergo IRC server

[Main documentation here.](https://github.com/ergochat/ergo-ldap)

For simple user auth prepare a ldap-config.yaml with the following settings

```
host: "127.0.0.1"
port: 3890
timeout: 30s

# uncomment for TLS / LDAPS:
# use-ssl: true

bind-dn: "uid=%s,ou=people,dc=example,dc=org"
```

Then add the compiled ergo-ldap program to your Ergo folder and make sure it can be executed by the same user your Ergo IRCd runs as.

Follow the instructions in the main Ergo config file's accounts section on how to execute an external auth program.

Make sure SASL auth is enabled and then restart Ergo to enable LDAP linked SASL auth.
