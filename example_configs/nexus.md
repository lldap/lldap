# Configuration for Sonatype Nexus Repository Manager 3
In Nexus log in as an administrator, go to `Server Administration and configuration (gear icon)` 

Select `LDAP` under the `Security` section

Click `Create connection`

* Host: A name for the connection e.g. lldap
* Type: ldap
* Host: Your lldap server's ip/hostname
* Port: Your lldap server's port (3890 by default)
* Base DN: `dc=example,dc=com`
* Authentication Method: Simple Authentication
* Username or DN: `uid=admin,ou=people,dc=example,dc=com` or preferably create a read only user in lldap with the lldap_strict_readonly group. 
* Password: The password for the user specified above

Click `Verify connection` if successful click `Next`

* Select a template: Generic ldap server
* User Relative DN: `ou=people`
* User subtree: Leave unchecked
* Object class: `person`
* User Filter:  Leave empty to allow all users to log in or `(memberOf=uid=nexus_users,ou=groups,dc=example,dc=com)` for a specific group
* Username Attribute: `uid`
* Real Name Attribute: `cn`
* Email Attribute: `mail`
* Password Attribute: Leave blank 
* Check `Enable User Synchronization`

Test user login credentials with `Verify login` 

## Set up group mapping as roles

Check `Map LDAP groups as roles`

* Group Type: `Static Groups`
* Group relative DN: `ou=groups`
* Group subtree: Leave unchecked
* Group object class: `groupOfUniqueNames`
* Group ID attribute: `cn`
* Group member attribute: `member`
* Group member format: `uid=${username},ou=people,dc=example,dc=com`

Check user mapping with `Verify user mapping`

## Map specific roles to groups
In Nexus log in as an administrator, go to `Server Administration and configuration (gear icon)`
Select `Roles` under the `Security` section

Click `Create Role`

* Role ID: e.g. nexus_admin (name in nexus)
* Role Name: e.g. nexus_admin (group in lldap)
* Add privileges/roles as needed e.g. under Roles add nx-admin to the "contained" list

Click `Save`
