# GitLab Configuration

## Placeholders
* Name for your LDAP server: ``LDAP``
* Host: ``ldap.example.com``
* Port: ``3890``
* Domain: ``dc=example,dc=com``
* Bind user: ``bind_user`` (has to be a member of the ``lldap_strict_readonly`` group)
* Bind user passwort: ``<bind user password>``
* Group of users that will have access to GitLab: ``git_user``

## Edit ``/etc/gitlab/gitlab.rb``:
```ruby
gitlab_rails['ldap_enabled'] = true
gitlab_rails['ldap_servers'] = {
  'main' => {
    'label' => 'LDAP',
    'host' =>  'ldap.example.com',
    'port' => 3890,
    'uid' => 'uid',
    'base' => 'ou=people,dc=example,dc=com',
    'encryption' => 'plain',
    'bind_dn' => 'uid=bind_user,ou=people,dc=example,dc=com',
    'password' => '<bind user password>',
    'active_directory' => false,
    'user_filter' => '(&(objectclass=person)(memberof=cn=git_user,ou=groups,dc=example,dc=com))',
    'attributes' => {
      'username' => 'uid',
      'email' => 'mail',
      'name' => 'cn',
      'first_name' => 'givenName',
      'last_name' => 'sn'
    }
  }
}
```
