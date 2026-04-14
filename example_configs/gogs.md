# Gogs LDAP configuration

## Via Simple Auth (easier)

Go to the Administration settings, then go to Authentication. There, you have to add an authentication source.

For type, select "LDAP (Simple Auth)".
Name your authentication source however you'd like. 
It is up to you to select your security protocol, but the only two compatible options are "LDAPS" and "Unencrypted". 
As your host, put in the IP or FQDN (if you have DNS).
As your port, check your configuration. It will generally be 389/3890 for unencrypted (once again check you config files), 636/6360 for LDAPS (once again check your config files).
Your User DN should look like `uid=%s,ou=people,dc=example,dc=com` if you have `dc=example,dc=com`, except if you changed your Base DN. In that case, remove the two last parts and add it at the end.
It is recommended to have your user filter to be `(&(objectClass=person)(uid=%s))`.
Your username attribute should be `uid`.
Your Given Name attribute should be `givenName`.
Your surname attribute should be `sn`.
Your email attribute should be `mail`.

You can (and should if you don't know LDAP) leave the rest empty.

## Via Bind DN (more complicated)

The following configuration is adapted from the example configuration at [their repository](https://github.com/gogs/gogs/blob/main/conf/auth.d/ldap_bind_dn.conf.example).
The example is a container configuration - the file should live within `conf/auth.d/some_name.conf`:

```yaml
$ cat /srv/git/gogs/conf/auth.d/ldap_bind_dn.conf
id           = 101
type         = ldap_bind_dn
name         = LDAP BindDN
is_activated = true
is_default   = true

[config]
host               = ldap.example.com
port               = 6360
# 0 - Unencrypted, 1 - LDAPS, 2 - StartTLS
security_protocol  = 1
# You either need to install the LDAPS certificate into your trust store -
# Or skip verification altogether - for a restricted container deployment a sane default.
skip_verify        = true
bind_dn            = uid=<binduser>,ou=people,dc=example,dc=com
bind_password      = `yourPasswordInBackticks`
user_base          = dc=example,dc=com
attribute_username = uid
attribute_name     = givenName
attribute_surname  = sn
attribute_mail     = mail
attributes_in_bind = false
# restricts on the `user_base`.
filter             = (&(objectClass=person)(uid=%s))
# The initial administrator has to enable admin privileges.
# This is only possible for users who were logged in once.
# This renders the following filter obsolete; Though its response is accepted by Gogs.
admin_filter       = (memberOf=cn=<yourAdminGroup>,ou=groups,dc=example,dc=com)
```

The `binduser` shall be a member of `lldap_strict_readonly`.
The group `yourAdminGroup` should be adapted to your requirement - Otherwise the entire line can be omitted.
The diamond brackets are for readability and are not required.

## Tested on Gogs

v0.14+dev via podman 4.3.1
