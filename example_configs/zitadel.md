# Configuration for Zitadel
In Zitadel, go to `Instance > Settings` for instance-wide LDAP setup or `<Organization Name> > Settings` for organization-wide LDAP setup.

## Identity Providers Setup
Click `Identity Providers` and select `Active Directory/LDAP`.

Replace every instance of `dc=example,dc=com` with your configured domain.
**Group filter is not supported at the time of writing.**
### Connection
* Name: The name to identify your identity provider
* Servers: `ldaps://<FQDN or Host IP>:<Port for LADPS>` or `ldap://<FQDN or Host IP>:<Port for LADP>` 
* BaseDn: `dc=example,dc=com`
* BindDn: `cn=admin,ou=people,dc=example,dc=com`. It is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.
* Bind Password: `<user password>`

### User binding
* Userbase: `ou=people,dc=example,dc=com`
* User filters: `uid`. `mail` will not work.
* User Object Classes: `inetOrgPerson`

### LDAP Attributes
* ID attribute: `uid`
* Avatar Url attribute: `jpegPhoto`
* Displayname attribute: `cn`
* Email attribute: `mail`
* Given name attribute: `givenName`
* Family name attribute: `sn`

### optional
* Account creation allowed [x]
* Account linking allowed [x]

**Either one of them or both of them must be enabled**

## Enable LDAP Login
Under `Settings`, select `Login Behavior and Security`

Under `Advanced`, enable `External IDP allowed`