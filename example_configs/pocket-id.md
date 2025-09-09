# LLDAP Configuration for Pocket-ID 

[Pocket-ID](https://pocket-id.org/) simple and easy-to-use OIDC provider that allows users to authenticate with their passkeys to your services.

|               |                         | Value                                                       |
|-----------------------|------------------------------------|-----------------------------------------------------------|
| **Client Configuration** | LDAP URL                           | ldaps://url:port                               
|                       | LDAP Bind DN                       | uid=binduser,ou=people,dc=example,dc=com              |
|                       | LDAP Bind Password                 | password for binduser                      |
|                       | LDAP Base DN                       | dc=example,dc=com                                         |
|                       | User Search Filter                 | (objectClass=person)                                      |
|                       | Groups Search Filter               | (objectClass=groupOfNames)                                |
|                       | Skip Certificate Verification      | true/false                                                 |
|                       | Keep disabled users from LDAP      | false                                               |
| **Attribute Mapping** | User Unique Identifier Attribute   | uuid                                                      |
|                       | Username Attribute                 | uid                                                       |
|                       | User Mail Attribute                | mail                                                      |
|                       | User First Name Attribute          | givenName                                                 |
|                       | User Last Name Attribute           | sn                                                        |
|                       | User Profile Picture Attribute     | jpegPhoto                                                 |
|                       | Group Members Attribute            | member                                                    |
|                       | Group Unique Identifier Attribute  | uuid                                                      |
|                       | Group Name Attribute               | cn                                                        |
|                       | Admin Group Name                   | pocketid_admin_group_name                                            |


Save and Sync.
