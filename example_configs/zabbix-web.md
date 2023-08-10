# Zabbix Web Configuration

This example is for the Zabbix Web interface version 6.0, which is the supported LTS version as of August 2023.  Later versions have additional options.

For the associated 6.0 documentation see [here](https://www.zabbix.com/documentation/6.0/en/manual/web_interface/frontend_sections/administration/authentication) and for the current manual see [here](https://www.zabbix.com/documentation/current/en/manual).

***Note that an LDAP user must exist in Zabbix Web as well, however its Zabbix password will not be used.*** When creating the user in Zabbix, the user should also be added to your desired Zabbix roles/groups.

## Configure LDAP Settings

- Log in to the web interface as an admin
- Navigate to `Administration > Authentication > LDAP Settings`

### Enable LDAP authentication

Checked

### LDAP host

URI of your LLDAP host. Example: `ldap://ldap.example.com:3890` or `ldaps://ldap.example.com:6360` for TLS.

### Port

Not used when using a full LDAP URI as above, but feel free to put `3890` or `6360` for TLS.

### Base DN

Your LLDAP_LDAP_BASE. Example: `dc=example,dc=com`

### Search attribute

`uid`

### Case-sensitive login

Checked

### Bind DN

`uid=admin,ou=people,dc=example,dc=com`

Alternately, it is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.

### Bind password

Password for the above bind DN user.

### Test authentication

The test authentication `Login` and `User password` must be used to check the connection and whether an LDAP user can be successfully authenticated. Zabbix will not activate LDAP authentication if it is unable to authenticate the test user.

## Enable LDAP in Zabbix Web

- Navigate to `Administration > Authentication > Authentication` (the first tab)
- Set "Default authentication" to "LDAP"
- Click "Update"
