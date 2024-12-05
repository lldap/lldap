# Configuration for OneDev
In Onedev, go to `Administration > External Authentication Source > Authenticator` and Select `Generic LDAP`

* LDAP URL: ldap://lldap_ip_or_hostname:3890 or ldaps://lldap_ip_or_hostname:6360
* Authentication Required: On
* Manager DN: `uid=admin,ou=people,dc=example,dc=com`
* Manager Password: Your bind user's password
* User Search Base: `ou=people,dc=example,dc=com`
* User Full Name Attribute: `displayName`
* Email Attribute: mail
* User SSH Key Attribute: (Leave Blank)
* Group Retrieval: "Search Groups Using Filter"
* Group Search Base: `ou=groups,dc=example,dc=com`
* Group Search Filter" `(&(uniqueMember={0})(objectclass=groupOfUniqueNames))`
* Group Name Attribute: cn
* Create User As Guest: Off
* Default Group: "No Default Group"
* Timeout: 300

Replace every instance of `dc=example,dc=com` with your configured domain.

After applying the above settings, users should be able to log in with their user name.
