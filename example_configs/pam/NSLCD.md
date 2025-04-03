# Configure lldap

You MUST use LDAPS. You MUST NOT use plain ldap. Even over a private network
this costs you nearly nothing, and passwords will be sent in PLAIN TEXT without
it.

```toml
[ldaps_options]
enabled=true
port=6360
cert_file="cert.pem"
key_file="key.pem"
```

You can generate an SSL certificate for it with the following command. The
`subjectAltName` is REQUIRED. Make sure all domains are listed there, even your
`CN`.

```sh
openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 36500 -nodes -subj "/CN=lldap.example.net" -addext "subjectAltName = DNS:lldap.example.net"
```

# Install the client packages.

This guide used `libnss-ldapd` (which is different from `libnss-ldap`).

PURGE the following ubuntu packages: `libnss-ldap`, `libpam-ldap`

Install the following ubuntu packages: `libnss-ldapd`, `nslcd`, `nscd`, `libpam-ldapd`

# Configure the client's `nslcd` settings.

Edit `/etc/nslcd.conf`. Use the [provided template](./nslcd.conf).

You will need to set `tls_cacertfile` to a copy of the public portion of your
LDAPS certificate, which must be available on the client. This is used to
verify the LDAPS server identity.

You will need to add the `binddn` and `bindpw` settings.

The provided implementation uses custom attributes to mark users and groups
that should be included in the system (for instance, you don't want LDAP
accounts of other services to have a matching unix user).

For users, you need to add an (integer) `unix-uid` attribute to the schema, and
manually set the value for the users you want to enable to login with PAM.

For groups, you need an (integer) `unix-gid` attribute, similarly set manually
to some value.

If you want to change this representation, update the `filter passwd` and
`filter group` accordingly.

You should check whether you need to edit the `pam_authz_search` setting. This
is used after authentication, at the PAM `account` stage, to determine whether
the user should be allowed to log in. If someone is an LDAP user, even if they
use an SSH key to log in, they must still pass this check. The provided example
will check for membership of a group named `YOUR_LOGIN_GROUP_FOR_THIS_MACHINE`.

You should review the `map` settings. These contain custom attributes that you
will need to add to lldap and set on your users.

# Configure the client OS.

Ensure the `nslcd` and `nscd` services are installed and running. `nslcd`
provides LDAP NSS service. `nscd` provides caching for NSS databased. You want
the caching.

```
systemctl enable --now nslcd nscd
```

Configure PAM to create the home directory for LDAP users automatically at
first login.

```
pam-auth-update --enable mkhomedir
```

Edit /etc/nsswitch.conf and add "ldap" to the END of the "passwd" and "group"
lines.

You're done!

## Clearing nscd caches.

If you want to manually clear nscd's caches, run `nscd -i passwd; nscd -i group`.

[scripting]: https://github.com/lldap/lldap/blob/main/docs/scripting.md

