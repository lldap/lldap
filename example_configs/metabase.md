# Configuring LDAP in Metabase

[Metabase](https://github.com/metabase/metabase) 

The simplest, fastest way to get business intelligence and analytics to everyone in your company 😋

---

## LDAP Host

```
example.com
```

## LDAP Port

```
3890
```

## LDAP Security
```
None
```

## Username or DN
It is recommended to use users belonging to the `lldap_strict_readonly` group
```
cn=adminro,ou=people,dc=example,dc=com
```

## Password
```
passwd
```

## User search base
```
ou=people,dc=example,dc=com
```

## User filter
Only users in the `metabase_users` group can log in
```
(&(objectClass=inetOrgPerson)(|(uid={login})(mail={login}))(memberOf=cn=metabase_users,ou=groups,dc=example,dc=com))
```

## Email attribute
```
mail
```

## First name attribute
```
givenname
```

## Last name attribute
```
cn
```

## Group Schema

**Synchronize Group Memberships**: Check this option to synchronize LDAP group memberships.

**New Mapping**: Create a new mapping between Metabase and LDAP groups:

- **Group Name**: `cn=metabase_users,ou=groups,dc=example,dc=com`

## Group search base

```
ou=groups,dc=example,dc=com
```

## Useful links

> [Metabase docker-compose.yaml](https://www.metabase.com/docs/latest/troubleshooting-guide/ldap)
