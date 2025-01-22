# Configuration for pgAdmin

The configuration for [pgAdmin][pgadmin] is done in the `config_local.py`. Refer
to the pgAdmin [documentation][config-doc] for guidance on its config file. The
[Enabling LDAP Authentication][ldap-authentication] describes all available
variables related to enable LDAP authentication for pgAdmin.

[pgadmin]: https://www.pgadmin.org/
[config-doc]: https://www.pgadmin.org/docs/pgadmin4/latest/config_py.html#config-py
[ldap-authentication]: https://www.pgadmin.org/docs/pgadmin4/latest/ldap.html

> [!NOTE]
> The configuration can also be done through the pgAdmin's `PGADMIN_CONFIG_*`
> [environnement variables][docker-variables] when run in Docker.

[docker-variables]: https://www.pgadmin.org/docs/pgadmin4/latest/container_deployment.html#environment-variables

Add and adapt the following in your `config_local.py` where:

- `dc=example,dc=com` is your LLDAP configured domain.
- `ldap://lldap:3890` is your `ldap://HOSTNAME-OR-IP:PORT` of your LLDAP server.
- `bind_user` and `REPLACE_ME` are your user uid and password of the bind user
  for pgAdmin.
- `pgadmin_users` is the group of the users you want to give access to pgAdmin.

```python
AUTHENTICATION_SOURCES = ["ldap"]
LDAP_AUTO_CREATE_USER = True
LDAP_SERVER_URI = "ldap://lldap:3890"
LDAP_USERNAME_ATTRIBUTE = "uid"
LDAP_BASE_DN = "ou=people,dc=example,dc=com"
LDAP_SEARCH_BASE_DN = "ou=people,dc=example,dc=com"
LDAP_BIND_USER = "uid=bind_user,ou=people,dc=example,dc=com"
LDAP_BIND_PASSWORD = "REPLACE_ME"
LDAP_SEARCH_FILTER = "(memberof=cn=pgadmin_users,ou=groups,dc=example,dc=com)"
```
