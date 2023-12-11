# Configuration for kasm

In kasm, go to *Admin* -> *Authentication* -> *LDAP* and add a configuration.
- *Name*: whatever you like
- *Url* is your lldap host (or IP) and port, e.g. `ldap://lldap.example.com:3890`
- *Search Base* is is your base dn, e.g `dc=example,dc=com`
- *Search Filter* is `(&(objectClass=person)(uid={0})(memberof=cn=kasm,ou=groups,dc=example,dc=com))`. Replace `cn=kasm,ou=groups,dc=example,dc=com` with the dn to the group necessary to login to kasm.
- *Group Membership Filter* `(&(objectClass=groupOfUniqueNames)(member={0}))`
- *Email attribute* `mail`
- *Service Account DN* a lldap user, preferably not a admin but a member of the group `lldap_strict readonly`. Mine is called  `cn=query,ou=people,dc=example,dc=com`
- *Service Account Password*: querys password
- Activate *Search Subtree*, *Auto Create App User* and *Enabled*
- under *Attribute Mapping* you can map the following:
	- *Email* -> `mail`
	- *First Name* -> `givenname`
	- *Last Name* -> `sn`
- If you want to map groups from your lldap to kasm, edit the group, scroll to *SSO Group Mappings* and add a new SSO mapping:
	- select your lldap as provider
	- *Group Attributes* is the full DN of your group, e.g. `cn=kasm_moreaccess,ou=groups,dc=example,dc=com`
