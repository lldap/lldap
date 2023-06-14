# Configuration for Zendto

You setup https://zend.to/ for using LDAP by editing `/opt/zendto/config/preferences.php`. The relevant part for LDAP-settings is 
```
  'authenticator'         => 'LDAP',
  'authLDAPBaseDN'        => 'DC=example,DC=com',
  'authLDAPServers'       => array('ldap://ldap_server_ip:3890'),
  'authLDAPAccountSuffix' => '@example.com',
  'authLDAPUseSSL'        => false,
  'authLDAPStartTLS'      => false,
  'authLDAPBindDn'        => 'uid=admin,ou=people,dc=example,dc=com',
  'authLDAPBindPass'      => 'your_password',
  'authLDAPUsernameAttr'  => 'uid',
  'authLDAPEmailAttr'     => 'mail',
  'authLDAPMemberKey'     => 'memberOf',
  'authLDAPMemberRole'    => 'cn=zendto,ou=groups,dc=example,dc=com',
```
Every user of the group `zendto` is allowed to login.
