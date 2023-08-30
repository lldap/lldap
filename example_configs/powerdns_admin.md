# Configuration for PowerDNS Admin

## Navigate

- Login to PowerDNS Admin
- Navigate to: `Administration > Settings > Authentication`
- Select the `LDAP` tab of the `Authentication Settings`

## LDAP Config

- Enable LDAP Authentication: Checked
- Type: OpenLDAP

### Administrator Info

- LDAP URI: `ldap://<your-lldap-ip-or-hostname>:3890`
- LDAP Base DN: `ou=people,dc=example,dc=com`
- LDAP admin username: `uid=admin,ou=people,dc=example,dc=com`
  - It is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.
- LDAP admin password: `password of the user specified above`

### Filters

- Basic filter: `(objectClass=person)`
- Username field: `uid`
- Group filter: `(objectClass=groupOfUniqueNames)`
- Group name field: `member`

### Group Security (Optional)

> If Group Security is disabled, all users authenticated via LDAP will be given the "User" role.

Group Security is an optional configuration for LLDAP users. It provides a simple 1:1 mapping between LDAP groups, and PowerDNS roles.

- Status: On
- Admin group: `cn=dns_admin,ou=groups,dc=example,dc=com`
- Operator group: `cn=dns_operator,ou=groups,dc=example,dc=com`
- User group: `cn=dns_user,ou=groups,dc=example,dc=com`
  