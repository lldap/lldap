# UniFi OS Identity End Point Configuration 

Below are the required settings to allow group syncing within UnifiOS Directory Integration, when enabling LDAP user sync 

- LDAP Version - OpenLDAP 
- LDAP Server - Your LLDAP Server IP Address - <For Example 10.128.20.3> ldap:// is not required in front of the IP address 
- Port - Your LLDAP Server Port - (either 6360 or 3890)
- Root DN - Your Root DN - (For Example dc=domain,dc=com)
- Bind DN - Your Bind DN - (For Example uid=ldapbinduser,ou=people,dc=domain,dc=com)
- Password - (Your Bind Password)
- Synced Scope - All 

After entering the LLDAP service details click the settings tab (the cog icon in the top right of the LDAP screen) in the UDMs Identity Endpoint setup screen, in the LDAP configuration settings enter 

## LDAP Config 

LDAP Version - OpenLDAP   
Unique Identifier Attribute - entryUUID 

### User 

- User Search Base - ou=people,dc=domain,dc=com 
- User Object Class - person 
- User Object Filter - objectClass=person 

### Group 

- Group Search Base - ou=groups,dc=domain,dc=com 
- Group Object Class - groupOfUniqueNames 
- Group Object Filter - objectClass=groupOfUniqueNames 

Member Attribute   
member 

Validate Attribute   
enter a user e-mail address who has been added in LLDAP , and click test configuration, test show be successful 

Advanced   
Delegated Authentication = true   
Suspend user Sync Feature = True 

Sync Scope   
Sync Scope - all 

You can now go back up to the top of the setup and amend your group mappings as required 

Group Mappings   
Edit Rule 

You can now select the required LLDAP group to sync with the UDM Identity group
