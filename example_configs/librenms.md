# Configuration for LibreNMS

You can either configure LibreNMS from the webui or from the command line. This is a list of the variables that you should set.

## Essential

## auth_ldap_uid_attribute

```    
uid
```
default: uidNumber

This sets 'uid' as the unique ldap attribue for users.

## auth_ldap_groupmemberattr

```
member
```
Default: memberUid

## auth_ldap_groups

```'
{"nms_admin": {"level": 10}}'
```
Default: {"admin": {"level": 10}}'

This example sets the group nms_admin as Admin (level 10).
Set others to match more groups at different levels.

## auth_ldap_starttls

```
false
```
Default: true

## auth_ldap_server

```
[lldap server ip]
```

## auth_ldap_port

```
3890
```
Default: 389

## auth_ldap_suffix

```
,ou=people,dc=example,dc=com
```

Default: ,ou=People,dc=example,dc=com`

Not sure if the case of people actually matters.
Make sure you keep the initial comma.

## auth_ldap_groupbase

```
ou=groups,dc=example,dc=com
```
Default: cn=groupname,ou=groups,dc=example,dc=com

## auth_mechanism

```
ldap
```
Default: mysql
Be careful with this as you will lock yourself out if ldap does not work correctly.

### auth_ldap_require_groupmembership

```
false
```
Default: true

## Testing

Use the test script to make sure it works.
```
./script/auth_test.php -u <user>
```
Make sure the level is correctly populated. Should look like this:

```
librenms:/opt/librenms# ./scripts/auth_test.php -uadmin
Authentication Method: ldap
Password:
Authenticate user admin:
AUTH SUCCESS

User (admin):
  username => admin
  realname => Administrator
  user_id => admin
  email => admin@example.com
  level => 10
Groups: cn=nms_admin,ou=groups,dc=example,dc=com
```

## Setting variables

### Web UI

You can set all the varibles in the web UI in: Settings -> Authentication -> LDAP Settings

### Command line

You can use the lnms command to *get* config options like this:
```
lnms config:get auth_ldap_uid_attribute
```

You can use the lnms command to *set* config options like this:
```
lnms config:set auth_ldap_uid_attribute uid
```

Read more [here](https://docs.librenms.org/Support/Configuration/)

### Pre load configuration for Docker

You can create a file named: /data/config/ldap.yaml and place your variables in there.

```
librenms:/opt/librenms# cat /data/config/auth.yaml
auth_mechanism: ldap

auth_ldap_server: 172.17.0.1
auth_ldap_port: 3890
auth_ldap_version: 3
auth_ldap_suffix: ,ou=people,dc=example,dc=com
auth_ldap_groupbase: ou=groups,dc=example,dc=com

auth_ldap_prefix: uid=
auth_ldap_starttls: False
auth_ldap_attr: {"uid": "uid"}
auth_ldap_uid_attribute: uid
auth_ldap_groups: {"nms_admin": {"level": 10}}
auth_ldap_groupmemberattr: member
auth_ldap_require_groupmembership: False
auth_ldap_debug: False

auth_ldap_group: cn=groupname,ou=groups,dc=example,dc=com
auth_ldap_groupmembertype: username
auth_ldap_timeout: 5
auth_ldap_emailattr: mail
auth_ldap_userdn: True
auth_ldap_userlist_filter:
auth_ldap_wildcard_ou: False
```

Read more [here](https://github.com/librenms/docker#configuration-management)

## Issue with current LibreNMS

The current version (23.7.0 at the time of writing) does not support lldap. A fix has been accepted to LibreNMS so the next version should just work.

[Link to the commit](https://github.com/librenms/librenms/commit/a71ca98fac1a75753b102be8b3644c4c3ee1a624)

If you want to apply the fix manually, run git apply with this patch.

```
diff --git a/LibreNMS/Authentication/LdapAuthorizer.php b/LibreNMS/Authentication/LdapAuthorizer.php
index 5459759ab..037a7382b 100644
--- a/LibreNMS/Authentication/LdapAuthorizer.php
+++ b/LibreNMS/Authentication/LdapAuthorizer.php
@@ -233,7 +233,7 @@ class LdapAuthorizer extends AuthorizerBase
         $entries = ldap_get_entries($connection, $search);
         foreach ($entries as $entry) {
             $user = $this->ldapToUser($entry);
-            if ((int) $user['user_id'] !== (int) $user_id) {
+            if ($user['user_id'] != $user_id) {
                 continue;
             }
 
@@ -360,7 +360,7 @@ class LdapAuthorizer extends AuthorizerBase
         return [
             'username' => $entry['uid'][0],
             'realname' => $entry['cn'][0],
-            'user_id' => (int) $entry[$uid_attr][0],
+            'user_id' => $entry[$uid_attr][0],
             'email' => $entry[Config::get('auth_ldap_emailattr', 'mail')][0],
             'level' => $this->getUserlevel($entry['uid'][0]),
         ];
```