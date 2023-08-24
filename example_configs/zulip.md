# Configuration for Zulip

Zulip combines the immediacy of real-time chat with an email threading model.

Their ldap-documentation is here: [zulip.readthedocs.io](https://zulip.readthedocs.io/en/stable/production/authentication-methods.html#ldap-including-active-directory)

Zulip has two installation methods, either by running the recommended installer or by docker/podman compose.
The way how the service is configured differs depending on the installation method, so keep in mind you will only need one of the following examples.

> Important info  
> The available/configured userdata will be automatically imported at the first login.  
> If you want to import it before the user logs in for the first time or  
> if you want to keep the data in sync with LLDAP you need to trigger the import by hand (or via cronjob).  
> `/home/zulip/deployments/current/manage.py sync_ldap_user_data`

## Container based configuration
The following configuration takes place in the environment section of your compose-file.

1) Enable the LDAP authentication backend  
Find the line`ZULIP_AUTH_BACKENDS: "EmailAuthBackend"` and change it to `ZULIP_AUTH_BACKENDS: "ZulipLDAPAuthBackend,EmailAuthBackend"`.

2) Configure how to connect with LLDAP  
The user specified in `SETTING_AUTH_LDAP_BIND_DN` is used to querry data from LLDAP.  
Zulip is only able to authenticate users and read data via ldap it is not able to write data or change the users password.  
Because of this limitation we will use the group `lldap_strict_readonly` for this user.  
Add the following lines to your configuration and change the values according to your setup.
```
SETTING_AUTH_LDAP_SERVER_URI: "ldap://lldap:3890"
SETTING_AUTH_LDAP_BIND_DN: "uid=zulip,ou=people,dc=example,dc=com"
SECRETS_auth_ldap_bind_password: "superSECURE_Pa55word"
```

3) Configure how to search for existing users  
Add the following lines to your configuration and change the values according to your setup.
```
SETTING_AUTH_LDAP_USER_SEARCH: >
  LDAPSearch("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)")
SETTING_LDAP_EMAIL_ATTR: mail
SETTING_AUTH_LDAP_REVERSE_EMAIL_SEARCH: >
  LDAPSearch("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(mail=%(email)s)")
SETTING_AUTH_LDAP_USERNAME_ATTR: "uid"
```

4) Configure the user-data mapping  
This step is optional, the sample below shows the maximum of available options, you can use all of them or none.  
Add the following lines to your configuration and remove the fields you don't want to be synced.  
The field `"full_name": "cn"` is mandatory.  
```
SETTING_AUTH_LDAP_USER_ATTR_MAP: >
  {"full_name": "cn","first_name": "givenName","last_name": "sn","avatar": "jpegPhoto"}
```

5) Configure which groups are allowed to authenticate  
This step is optional, if you do not specify anything here all users from your LLDAP server will be able to login.  
This example will grant access to all users who are a member of `zulip_users`.  
Add the following lines to your configuration and change the values according to your setup.  
```
ZULIP_CUSTOM_SETTINGS: "import django_auth_ldap"
SETTING_AUTH_LDAP_GROUP_TYPE: "django_auth_ldap.config.GroupOfUniqueNamesType(name_attr='cn')"
SETTING_AUTH_LDAP_REQUIRE_GROUP: "cn=zulip_users,ou=groups,dc=example,dc=com"
SETTING_AUTH_LDAP_GROUP_SEARCH: >
  LDAPSearch("ou=groups,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=GroupOfUniqueNames)")
```

6) Disallow local changes after importing userdata  
This step is optional, you may want disallow the user to change their name and avatar if you import this data via ldap.
Add the following lines to your configuration and change the values according to your setup.
```
SETTING_NAME_CHANGES_DISABLED: True
SETTING_AVATAR_CHANGES_DISABLED: True
```

## Installer based configuration
The following configuration takes place in the configuration-file `/etc/zulip/settings.py`.

1) Enable the LDAP authentication backend  
Find the line `AUTHENTICATION_BACKENDS` and uncomment `"zproject.backends.ZulipLDAPAuthBackend"`.

2) Configure how to connect with LLDAP  
The user specified in `AUTH_LDAP_BIND_DN` is used to querry data from LLDAP.  
Zulip is only able to authenticate users and read data via ldap it is not able to write data or change the users password.  
Because of this limitation we will use the group `lldap_strict_readonly` for this user.  
Uncomment the following lines in your configuration and change the values according to your setup.
```
AUTH_LDAP_SERVER_URI = "ldap://lldap:3890"
AUTH_LDAP_BIND_DN = "uid=zulip,ou=people,dc=example,dc=com"
```

The password corresponding to AUTH_LDAP_BIND_DN goes in `/etc/zulip/zulip-secrets.conf`.  
Add a single new line to that file like below.
```
auth_ldap_bind_password = superSECURE_Pa55word
```

3) Configure how to search for existing users  
Uncomment the following lines in your configuration and change the values according to your setup.
```
AUTH_LDAP_USER_SEARCH = LDAPSearch("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)")
LDAP_EMAIL_ATTR = mail
AUTH_LDAP_REVERSE_EMAIL_SEARCH = LDAPSearch("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(mail=%(email)s)")
AUTH_LDAP_USERNAME_ATTR = "uid"
```

4) Configure the user-data mapping  
This step is optional, the sample below shows the maximum of available options, you can use all of them or none.  
Find the line `AUTH_LDAP_USER_ATTR_MAP`, then uncomment the values you want to map and change the values according to your setup.
```
AUTH_LDAP_USER_ATTR_MAP = {
    "full_name": "cn",
    "first_name": "givenName",
    "last_name": "sn",
    "avatar": "jpegPhoto",
}
```

5) Configure which groups are allowed to authenticate  
This step is optional, if you do not specify anything here all users from your LLDAP server will be able to login.  
This example will grant access to all users who are a member of `zulip_users`.  
Add the following lines to your configuration and change the values according to your setup.  
```
import django_auth_ldap
AUTH_LDAP_GROUP_TYPE = "django_auth_ldap.config.GroupOfUniqueNamesType(name_attr='cn')"
AUTH_LDAP_REQUIRE_GROUP = "cn=zulip_users,ou=groups,dc=example,dc=com"
AUTH_LDAP_GROUP_SEARCH = LDAPSearch("ou=groups,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=GroupOfUniqueNames)")
```

6) Disallow local changes after importing userdata  
This step is optional, you may want disallow the user to change their name and avatar if you import this data via ldap.
Uncomment the following lines in your configuration and change the values according to your setup.
```
NAME_CHANGES_DISABLED: True
AVATAR_CHANGES_DISABLED: True
```
