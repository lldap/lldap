# Mailcow LLDAP example config

## Setting location

First, go to `System` > `Configuration`.

And then, `Access` > `Identity Provider`.

## Configuration

Set `Identity Provider` as `LDAP`

Set `Host` as the LLDAP IP.

Set `Port` as the LLDAP port, which should be `3890` by default.

Set `Use SSL` to `False`.

Set `Use StartTLS` (SSL port will not be used) to `False`.

Set `Ignore SSL Errors` (validation bypass) to `False`.

When using `Use SSL` (LDAPS), `Port` should be set to `6360` instead, the default port if unchanged.

These three options should be `False`, unless there is a properly-signed non self-signed certificate for LLDAP installed.

Set `Base DN` in the format like `dc=example,dc=org`.

Set `Username Field` as `mail` or `uid`.

Set `Filter` as `(objectclass=person)`.

Set `Attribute Field` also as `mail`.

Set `Bind DN` in the format like `uid=username,ou=people,dc=example,dc=org`.

Set `Bind Password` as the password of the user given in `Bind DN`

Leave `Attribute Mapping` as default if you not sure what it means.

Set `Auto-create users on login`, `Periodic Full Sync`, `Import Users` to `True`.

Set `Sync / Import interval (min)` to `15`

Try `Test Connection`, you should be able to connect it now.
