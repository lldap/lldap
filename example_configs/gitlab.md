# GitLab Configuration

Members of the group ``git_user`` will have access to GitLab.

Edit ``/etc/gitlab/gitlab.rb``:

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
      'name' => 'displayName',
      'first_name' => 'givenName',
      'last_name' => 'sn'
    }
  }
}
```
