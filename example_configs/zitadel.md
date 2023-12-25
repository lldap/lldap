# Configuration for Zitadel
In Zitadel, go to `Instance > Settings` for instance-wide LDAP setup or `<Organization Name> > Settings` for organization-wide LDAP setup.

## Identity Providers Setup
Click `Identity Providers` and select `Active Directory/LDAP`.

**Group filter is not supported in `Zitadel` at the time of writing.**

Replace every instance of `dc=example,dc=com` with your configured domain.
### Connection
* Name: The name to identify your identity provider
* Servers: `ldaps://<FQDN or Host IP>:<Port for LADPS>` or `ldap://<FQDN or Host IP>:<Port for LADP>` 
* BaseDn: `dc=example,dc=com`
* BindDn: `cn=admin,ou=people,dc=example,dc=com`. It is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.
* Bind Password: `<user password>`

### User binding
* Userbase: `dn`
* User filters: `uid`. `mail` will not work.
* User Object Classes: `person`

### LDAP Attributes
* ID attribute: `uid`
* displayName attribute: `cn`
* Email attribute: `mail`
* Given name attribute: `givenName`
* Family name attribute: `lastName`
* Preferred username attribute: `uid`

### optional
The following section applied to `Zitadel` only, nothing will change on `LLDAP` side.

* Account creation allowed [x]
* Account linking allowed [x]

**Either one of them or both of them must be enabled**

**DO NOT** enable `Automatic update` if you haven't setup a smtp server. Zitadel will update account's email and sent a verification code to verify the address. 
If you don't have a smtp server setup correctly and the email adress of `ZITADEL Admin` is changed, you are **permanently** locked out.

`Automatic creation` can automatically create a new account without user interaction when `Given name attribute`, `Family name attribute`, `Email attribute`, and `Preferred username attribute` are presented.

## Enable Identity Provider
After clicking `Save`, you will be redirected to `Identity Providers` page.

Enable the LDAP by hovering onto the item and clicking the checkmark (`set as available`)

## Enable LDAP Login
Under `Settings`, select `Login Behavior and Security`

Under `Advanced`, enable `External IDP allowed`