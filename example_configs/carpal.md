# Configuration for Carpal

[Carpal](https://github.com/peeley/carpal) is a small, configurable
[WebFinger](https://webfinger.net) server than can pull resource information
from LDAP directories.

There are two files used to configure Carpal for LDAP:

- The YAML configuration file for Carpal itself
- A Go template file for injecting the LDAP data into the WebFinger response

### YAML File

Replace the server URL, admin credentials, and domain for your server:

```yaml
# /etc/carpal/config.yml

driver: ldap
ldap:
  url: ldap://myldapserver
  bind_user: uid=myadmin,ou=people,dc=foobar,dc=com
  bind_pass: myadminpassword
  basedn: ou=people,dc=foobar,dc=com
  filter: (uid=*)
  user_attr: uid
  attributes:
    - uid
    - mail
    - cn
  template: /etc/carpal/ldap.gotempl
```

If you have configured any user-defined attributes on your users, you can also
add those to the `attributes` field.

### Go Template File

This is an example template; the template file is intended to be editable for
your needs. If your users, for example, don't have Mastodon profiles, you can
delete the Mastodon alias.

```gotempl
# /etc/carpal/ldap.gotempl

aliases:
  - "mailto:{{ index . "mail" }}"
  - "https://mastodon/{{ index . "uid" }}"
properties:
  'http://webfinger.example/ns/name': '{{ index . "cn" }}'
links:
  - rel: "http://webfinger.example/rel/profile-page"
    href: "https://www.example.com/~{{ index . "uid" }}/"
```

This example also only contains the default attributes present on all LLDAP
users. If you have added custom user-defined attributes to your users and added
them to the `attributes` field of the YAML config file, you can use them in
this template file.
