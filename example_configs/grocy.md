# Configuration for Grocy

Adjust the following values in the file `config/data/config.php` or add environment variables for them (prefixed with `GROCY_`).

NOTE: If the environment variables are not working (for example in the linuxserver.io Docker Image), you need to add `clear_env = no` under the `[www]` in `/config/php/www2.conf`.

Replace `dc=example,dc=com` with your LLDAP configured domain.

### AUTH_CLASS
Needs to be set to `Grocy\Middleware\LdapAuthMiddleware` in order to use LDAP

### LDAP_ADDRESS
The address of your ldap server, eg: `ldap://lldap.example.com:389`

### LDAP_BASE_DN
The base dn, usually points directly to the `people`, eg: `ou=people,dc=example,dc=com`

### LDAP_BIND_DN
The reader user for lldap, eg: `uid=ldap-reader,ou=people,dc=example,dc=com`

### LDAP_BIND_PW
The password for the reader user

### LDAP_USER_FILTER
The filter to use for the users, eg. for a separate group: `(&(objectClass=person)(memberof=cn=grocy_users,ou=groups,dc=example,dc=com))`

### LDAP_UID_ATTR
The user id attribute, should be `uid`
