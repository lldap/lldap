# Configuration for Authelia

## Authelia LDAP configuration

For all configuration options see the [Authelia LDAP Documentation](https://www.authelia.com/configuration/first-factor/ldap/).

The following example configuration uses the LLDAP implementation template, the default values are documented in the
[Authelia LLDAP Integration Guide](https://www.authelia.com/integration/ldap/lldap/).

Users will be able to sign in using their username or email address.

```yaml
authentication_backend:
  # How often authelia should check if there is a user update in LDAP
  refresh_interval: '1m'
  ldap:
    implementation: 'lldap'
    # Format is [<scheme>://]<hostname>[:<port>]
    # ldap port for LLDAP is 3890 and ldaps 6360
    address: 'ldap://lldap:3890'
    # Set base dn that you configured in LLDAP
    base_dn: 'DC=example,DC=com'
    # The username and password of the bind user.
    # "bind_user" should be the username you created for authentication with the "lldap_strict_readonly" permission. It is not recommended to use an actual admin account here.
    # If you are configuring Authelia to change user passwords, then the account used here needs the "lldap_password_manager" permission instead.
    user: 'UID=bind_user,OU=people,DC=example,DC=com'
    # Password can also be set using a secret: https://www.authelia.com/configuration/methods/secrets/.
    password: 'REPLACE_ME'

  # Disable the authelia password change and reset functionality if the "bind_user" does not have the "lldap_password_manager" permission.
  password_reset:
    disable: false
  password_change:
    disable: false
```