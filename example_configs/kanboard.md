# configuration for Kanboard

add these to the kanboard `config.php`

Make sure you adapt `LDAP_SERVER` to the correct LDAP endpoint.

You also might have to change `dc=example,dc=com` to whatever your LLDAP is handling, and maybe change the `lldap_kanboard` group name used in `LDAP_USER_FILTER` to identify users of a valid group of yours.

```
define('LDAP_AUTH', true);
define('LDAP_SERVER', 'ldap://YOUR_LDAP_SERVER:3890');
define('LDAP_SSL_VERIFY', true);
define('LDAP_START_TLS', false);

define('LDAP_USERNAME_CASE_SENSITIVE', false);
define('LDAP_USER_CREATION', true);

define('LDAP_BIND_TYPE', 'user');
define('LDAP_USERNAME', 'uid=%s,ou=people,dc=example,dc=com');
define('LDAP_PASSWORD', null);

define('LDAP_USER_BASE_DN', 'ou=people,dc=example,dc=com');

define('LDAP_USER_FILTER', '(&(uid=%s)(memberof=cn=lldap_kanboard,ou=groups,dc=example,dc=com))');
define('LDAP_USERNAME_CASE_SENSITIVE', false);

define('LDAP_USER_ATTRIBUTE_USERNAME', 'uid');
define('LDAP_USER_ATTRIBUTE_FULLNAME', 'cn');
define('LDAP_USER_ATTRIBUTE_EMAIL', 'mail');
define('LDAP_USER_ATTRIBUTE_GROUPS', 'memberof');
define('LDAP_USER_ATTRIBUTE_PHOTO', '');
define('LDAP_USER_ATTRIBUTE_LANGUAGE', '');
```
