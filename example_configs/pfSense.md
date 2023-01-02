# Configuration for pfSense

Note: Using the test feature in pfSense does not appear to work, and LDAP users do not appear in the Users tab, 
these are likely bugs in pfSense.

This is only a basic configuration, allowing all valid users in the group to have full permissions.

Go to System > User Manager > Authentication Servers and Add.

Use the following settings. Non-default options are bolded. 
Assuming `dc=example,dc=com` and a user for authentication called `cn=auth` in `lldap_strict_readonly`.

| Key                               | Value                                                                                                                                                             |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Hostname or IP address**        | Address of LDAP server                                                                                                                                            |
| Port value                        | `389`                                                                                                                                                             |
| Transport                         | `Standard TCP`                                                                                                                                                    |
| Peer certificate authority        | `Global Root CA List`                                                                                                                                             |
| Protocol version                  | `3`                                                                                                                                                               |
| Server timeout                    | `25`                                                                                                                                                              |
| **Search scope level**            | `Entire subtree`                                                                                                                                                  |
| **Search scope base DN**          | `dc=example,dc=com`                                                                                                                                               |
| **Authentication containers**     | `ou=people`                                                                                                                                                       |
| **Extended query**                | enabled                                                                                                                                                           |
| **Query**                         | `&(objectClass=person)(memberof=cn=admins,ou=groups,dc=example,dc=com)` This will require users to be in the `admins` group. Remove that part to allow all users. |
| **Bind anonymous**                | disabled (if desired, also set credentials if disabling)                                                                                                          |
| **Bind credentials**              | username: `cn=auth,ou=people,dc=example,dc=com`                                                                                                                   |
| **User naming attribute**         | `uid`                                                                                                                                                             |
| Group naming attribute            | `cn`                                                                                                                                                              |
| **Group member attribute**        | `memberUid`                                                                                                                                                       |
| **RFC 2307 Groups**               | enabled                                                                                                                                                           |
| RFC 2307 User DN                  | disabled                                                                                                                                                          |
| **Group Object Class**            | `group`                                                                                                                                                           |
| **Shell Authentication Group DN** | optional                                                                                                                                                          |
| UTF8 Encode                       | disabled (may be supported but was not tested)                                                                                                                    |
| Username Alterations              | disabled                                                                                                                                                          |
| **Allow unauthenticated bind**    | disabled                                                                                                                                                          |

Save and change to the Settings tab. Change Authentication Server to the one you just created and save.
You will still be able to log in with the local database.

Change to the Groups tab.
Add a new group (here called `pfsense_admin`), your user(s) will of course need to be in the group.

| Key              | Value                            |
|------------------|----------------------------------|
| **Group name**   | `pfsense_admin`                  |
| **Scope**        | `Remote`                         |
| **Description**  | Can be anything, but is required |
| Group membership | Do not add any users             |

Save the group, then click the edit button. In the Assigned Privileges section, click Add then select all permissions.
Save and save.
