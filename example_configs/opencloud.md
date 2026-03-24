# OpenCloud example config


## About OpenCloud

A light-weight file-hosting / webDAV service written in Go and forked from ownCloud Infinite Scale (oCIS).

More information:
  * https://opencloud.eu
  * https://github.com/opencloud-eu


## LLDAP Configuration

OpenCloud ships an OIDC provider and a built-in LDAP server. It officially supports using a third-party OIDC provider.

This is **not** what this config does. This config leaves the general auth/OIDC infrastructure in place, but replaces the LDAP server from underneath it with LLDAP.

Configuration happens via environment variables. On FreeBSD, these are provided via `/usr/local/etc/opencloud/config.env`; on Linux you can provide them via the Docker configuration.


```dotenv
# Replace with actual IP and Port
OC_LDAP_URI=ldap://<lldap_ip>:3890
# Remove the following if you use LDAPS and your cert is not self-signed
OC_LDAP_INSECURE="true"

# Replace with your bind-user; can be in
OC_LDAP_BIND_DN="cn=<bind_user>,ou=people,dc=example,dc=com"
OC_LDAP_BIND_PASSWORD="<secret>"

OC_LDAP_GROUP_BASE_DN="ou=groups,dc=example,dc=com"
OC_LDAP_GROUP_SCHEMA_ID=entryuuid

OC_LDAP_USER_BASE_DN="ou=people,dc=example,dc=com"
OC_LDAP_USER_SCHEMA_ID=entryuuid

# Only allow users from specific group to login; remove this if everyone's allowed
OC_LDAP_USER_FILTER='(&(objectClass=person)(memberOf=cn=<opencloud_users>,ou=groups,dc=example,dc=com))'

# Other options have not been tested
OC_LDAP_DISABLE_USER_MECHANISM="none"

# If you bind-user is in lldap_strict_readonly set to false (this hides "forgot password"-buttons)
OC_LDAP_SERVER_WRITE_ENABLED="false"
# If your bind-user can change passwords:
OC_LDAP_SERVER_WRITE_ENABLED="true"       # Not tested, yet!

# Don't start built-in LDAP, because it's replaced by LLDAP
OC_EXCLUDE_RUN_SERVICES="idm"
```

There is currently no (documented) way to give an LDAP user (or group) admin rights in OpenCloud.

See also [the official LDAP documentation](https://github.com/opencloud-eu/opencloud/blob/main/devtools/deployments/opencloud_full/ldap.yml).
