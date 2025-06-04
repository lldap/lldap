# LLDAP Configuration

1. Create a group for PocketID Admins; e.g: `pocketid_admin`.

2. Create an admin user for PocketID; e.g: `pocketid`.

3. Add this user (`pocketid`) to the group for PocketID admins (`pocketid_admin`).

---

# PocketID LDAP Settings

## Client Configuration

| Field                         | Value                                        |
| ----------------------------- | -------------------------------------------- |
| LDAP URL                      | `ldaps://lldap.yourdomain.com:6360`          |
| LDAP Bind DN                  | `cn=pocketid,ou=people,dc=yourdomain,dc=com` |
| LDAP Bind Password            | `the-user-pocketid's-password`               |
| LDAP Base DN                  | `dc=yourdomain,dc=com`                       |
| User Search Filter            | `(objectClass=person)`                       |
| Group Search Filter           | `(objectClass=groupOfNames)`                 |
| Skip Certificate Verification | `false`                                      |
| Keep disabled users from LDAP | `true` (Personal Preference)                 |

## Attribute Mapping

| Attribute                         | Value            |
| --------------------------------- | ---------------- |
| User Unique Identifier Attribute  | `uuid`           |
| Username Attribute                | `user_id`        |
| User Mail Attribute               | `mail`           |
| User First Name Attribute         | `first_name`     |
| User Last Name Attribute          | `last_name`      |
| User Profile Picture Attribute    | `avatar`         |
| Group Members Attribute           | `member`         |
| Group Unique Identifier Attribute | `uuid`           |
| Group Name Attribute              | `cn`             |
| Admin Group Name                  | `pocketid_admin` |


