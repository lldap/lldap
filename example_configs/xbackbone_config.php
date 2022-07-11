<?php
return array (
  'ldap' =>
  array (
    'enabled' => true,
    'schema' => 'ldap',
    // If using same docker network, use 'lldap', otherwise put ip/hostname
    'host' => 'lldap',
    // Normal ldap port is 389, standard in LLDAP is 3890
    'port' => 3890,
    'base_domain' => 'ou=people,dc=example,dc=com',
    // ???? is replaced with user-provided username, authenticates users in an lldap group called "xbackbone"
    // Remove the "(memberof=...)" if you want to allow all users.
    'search_filter' => '(&(uid=????)(objectClass=person)(memberof=cn=xbackbone,ou=groups,dc=example,dc=com))',
    // the attribute to use as username
    'rdn_attribute' => 'uid',
    // LDAP admin/service account info below
    'service_account_dn' => 'cn=admin,ou=people,dc=example,dc=com',
    'service_account_password' => 'REPLACE_ME',
  ),
);
