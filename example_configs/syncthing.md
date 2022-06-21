# Configuration for Syncthing
##  Actions > Advanced > LDAP
---

| Parameter            | Value                                                                  | Details                                               |
|----------------------|------------------------------------------------------------------------|-------------------------------------------------------|
| Address              | `localhost:3890`                                                       | Replace `localhost:3890` with your LLDAP host & port  |
| Bind DN              | `cn=%s,ou=people,dc=example,dc=com`                                    |                                                       |
| Insecure Skip Verify | *unchecked*                                                            |                                                       |
| Search Base DN       | `ou=people,dc=example,dc=com`                                          | Only used when using filters.                         |
| Search Filter        | `(&(uid=%s)(memberof=cn=lldap_syncthing,ou=groups,dc=example,dc=com))` | Filters on users belonging to group `lldap_syncthing` |
| Transport            | `plain`                                                                |                                                       |

Replace `dc=example,dc=com` with your LLDAP configured domain for all occurances

Leave **Search Base DN** and **Search Filter** both blank if you are not using any filters.

##  Actions > Advanced > GUI

Change **Auth Mode** from `static` to `ldap`


If you get locked out of the UI due to invalid LDAP settings, you can always change the settings from the `config.xml`, save the file, and force restart the app.

### Example

Change the below and restart

` <authMode>ldap</authMode>` to ` <authMode>static</authMode>`

