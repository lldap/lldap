# Penpot Configuration

Penpot is the only design & prototype platform that is deployment agnostic. You can use it or deploy it anywhere.

## LDAP Config

Penpot comes with support for Lightweight Directory Access Protocol.

[Penpot documentation](https://help.penpot.app/technical-guide/configuration/#ldap)

example of configuration:

```yaml
PENPOT_LDAP_HOST: lldap.shared.svc.cluster.local
PENPOT_LDAP_PORT: 3890
PENPOT_LDAP_SSL: false
PENPOT_LDAP_STARTTLS: false
PENPOT_LDAP_BASE_DN: ou=people,dc=example,dc=com
PENPOT_LDAP_USER_QUERY: (&(|(uid=:username)(mail=:username))(memberOf=cn=penpot,ou=groups,dc=example,dc=com))
PENPOT_LDAP_ATTRS_USERNAME: uid
PENPOT_LDAP_ATTRS_EMAIL: mail
PENPOT_LDAP_ATTRS_FULLNAME: uid
PENPOT_LDAP_ATTRS_PHOTO: jpegPhoto
PENPOT_LDAP_BIND_DN: "uid=penpot_bind_user,ou=people,dc=in,dc=example,dc=com"
PENPOT_LDAP_BIND_PASSWORD: "penpot_bind_password"
```
It is important to note that `PENPOT_LDAP_ATTRS_FULLNAME` must be set to `uid`, not `cn`, as fullname in LLDAP is not mandatory, but this field is required for Penpot.
