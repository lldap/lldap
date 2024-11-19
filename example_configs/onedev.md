# Configuration for Onedev
In Onedev, go to `Administration > Authentication Sources` and click `External Authentication`
Select `Generic LDAP`

* LDAP URL: Your lldap server's ip/hostname
* Authentication Required: On
* Manager DN: `uid=admin,ou=people,dc=example,dc=com`
* Manager Password: Your bind user's password
* User Search Base: `ou=people,dc=example,dc=com`
* User Filter:  If you want all users to be able to log in, use<br>
  `(&(uid={0})(objectclass=person))`.<br>
* User Full Name Attribute: (Leave Blank)
* Email Attribute: mail
* User SSH Key Attribute: (Leave Blank)
* Group Retrieval: "Get Groups Using Attribute"
* User Groups Attribute: uniquemember
* Group Name Attribute: cn
* Create User As Guest: Off
* Default Group: "No Default Group"
* Timeout: 300

Replace every instance of `dc=example,dc=com` with your configured domain.

After applying the above settings, users should be able to log in with their user name.
