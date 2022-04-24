# Configuration pour Dolibarr

## This example will help you to create user in dolibarr from your users in your lldap server from a specific group and to login with the password from the lldap server.

## to connect ldap->dolibarr 

Install module LDAP from Home -> Modules/Applications
Go to the configuration of this module and fill it like this:


Users and groups synchronization: LDAP -> Dolibarr
Contacts' synchronization: No
Type: OpenLdap
Version: Version 3
Primary server: ldap://example.com
Secondary server: Empty
Server port: port 389
Server DN: dc=example,dc=com
Use TLS:  No
Administrator DN: cn=admin,ou=people,dc=example,dc=com
Administrator password: secret

Click on modify then "test ldap connection". 
You should get this result on the bottom:
```
 TCP connect to LDAP server successful (Server=ldap://example.com, Port=389)
Connect/Authenticate to LDAP server successful (Server=ldap://example.com, Port=389, Admin=cn=admin,ou=people,dc=example,dc=com, Password=**********)
LDAP server configured for version 3
```

And two new tabs will appear on the top:
Users and Groups

We will use only Users in this example to get the users we want to import.
The tab Groups would be to import groups.

Click on the Users tab and fill it like this:
Users' DN: ou=people,dc=example,dc=com
List of objectClass: person
Search filter: memberOf=cn=yournamegroup,ou=groups,dc=example,dc=com

Full name: cn
Name: sn
First name: givenname
Login uid
Email address mail

Click on MODIFY and then on TEST A LDAP SEARCH

You should get the number of users in the group.


##To import ldap users into the dolibarr database (needed to login with those users):

Navigate to  Users & Groups -> New Users
Click on the blank form "Users in LDAP database", you will get te list of the users in the group filled above. With the "GET" button, you will import the selected user.


##To enable LDAP login:

Modify you conf.php in your dolibarr folder in htdocs/conf
Add those lines:
```
// Authentication settings
// Only  add "ldap" to only login using the ldap server, or/and "dolibar" to compare with local users. In any case, you need to have the user existing in dolibarr.
$dolibarr_main_authentication='ldap,dolibarr'; 
$dolibarr_main_auth_ldap_host='ldap://127.0.0.1:389';
$dolibarr_main_auth_ldap_port='389';
$dolibarr_main_auth_ldap_version='3';
$dolibarr_main_auth_ldap_servertype='openldap';
$dolibarr_main_auth_ldap_login_attribute='cn';
$dolibarr_main_auth_ldap_dn='ou=people,dc=example,dc=com';
$dolibarr_main_auth_ldap_admin_login='cn=admin,ou=people,dc=example,dc=com';
$dolibarr_main_auth_ldap_admin_pass='secret;
```

You can add this line to enable debug in case anything is wrong:
```
$dolibarr_main_auth_ldap_debug='true';
```


