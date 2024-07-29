# Configuration for Prosody XMPP server

Prosody is setup with virtual hosts, at least one. If you want to have users access only specific virtual hosts, create a group per vHost (I called it `xmpp-example.com`). If not, remove the memberOf part in the filter below. I would also create a read only user (mine is called `query`) with the group `lldap_strict_readonly` to find the users that will be used to bind.

In `prosody.cfg.lua` you need to set `authentication` to `ldap` and the following settings:

```authentication = "ldap"
ldap_base = "dc=example,dc=com"
ldap_server = "localhost:3890"
ldap_rootdn = "uid=query,ou=people,dc=example,dc=com"
ldap_password = "query-password"
ldap_filter = "(&(uid=$user)(memberOf=cn=xmpp-$host,ou=groups,dc=example,dc=com)(objectclass=person))"
```

Restart Prosody and you should be good to go.
