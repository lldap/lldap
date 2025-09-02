# Open-WebUI LDAP configuration

For the GUI settings (recommended) go to:
`Admin Panel > General`.
There you find the LDAP config.

For the initial activation, restart OpenWebUI to load the LDAP module.

The following configurations have to be provided.
The user `binduser` has to be member of `lldap_strict_readonly`.

| environment variable | GUI variable | example value | elaboration |
|----------------------|--------------|---------------|-------------|
| `ENABLE_LDAP` | LDAP | `true` | Toggle |
| `LDAP_SERVER_LABEL` | Label | `any` (lldap) | name |
| `LDAP_SERVER_HOST` | Host | `ldap.example.org` | IP/domain without scheme or port |
| `LDAP_SERVER_PORT` | Port | `6360` | When starting Open-WebUI sometimes it only accepts the default LDAP or LDAPS port (only ENV configuration) |
| `LDAP_ATTRIBUTE_FOR_MAIL` | Attribute for Mail | `mail` | default |
| `LDAP_ATTRIBUTE_FOR_USERNAME` | Attribute for Username | `uid` | default |
| `LDAP_APP_DN` | Application DN | `uid=binduser,ou=people,dc=example,dc=org` | Hovering shows: Bind user-dn |
| `LDAP_APP_PASSWORD` | Application DN Password | `<binduser-pw>` | - |
| `LDAP_SEARCH_BASE` | Search Base | `ou=people,dc=example,dc=org` | Who should get access from your instance. |
| `LDAP_SEARCH_FILTER` | Search Filter | `(objectClass=person)` or `(\|(objectClass=person)(memberOf=cn=webui-members,ou=groups,dc=example,dc=org))` | Query for Open WebUI account names. |
| `LDAP_USE_TLS` | TLS | `true` | Should be `true` for LDAPS, `false` for plain LDAP |
| `LDAP_CA_CERT_FILE` | Certificate Path | `/ca-chain.pem` | required when TLS activated |
| `LDAP_VALIDATE_CERT` | Validate Certificate | `true` | Set to `false` for self-signed certificates |
| `LDAP_CIPHERS` | Ciphers | ALL | default |

## Tested on Open WebUI

v0.6.26 via podman 5.4.2
