[Harbor](https://goharbor.io) is a CNCF cloud native container registry for kubernetes. 

You can pass environment variables into ``harbor-core`` for auth configuration as documented [here](https://github.com/goharbor/website/blob/release-2.10.0/docs/install-config/configure-system-settings-cli.md#harbor-configuration-items).

Configure ``ldap_url`` and ``ldap_verify_cert`` as needed for your installation.

Using the [harbor-helm](https://github.com/goharbor/harbor-helm) chart, these vars can be passed in under ``core.configureUserSettings`` as a JSON string:

```yaml
core:
  configureUserSettings: |
    {
      "auth_mode": "ldap_auth",
      "ldap_url": "ldaps://lldap.example.com",
      "ldap_base_dn": "ou=people,dc=example,dc=com",
      "ldap_search_dn": "uid=bind,ou=people,dc=example,dc=com",
      "ldap_search_password": "very-secure-password",
      "ldap_group_base_dn": "ou=groups,dc=example,dc=com",
      "ldap_group_admin_dn": "cn=harbor-admin-group,ou=groups,dc=example,dc=com",
      "ldap_group_search_filter": "(objectClass=groupOfUniqueNames)",
      "ldap_group_attribute_name": "uid"
    }
```

> [!IMPORTANT]  
> ``ldap_search_dn`` needs to be able to bind and search. The ``lldap_strict_readonly`` group is sufficient.

> [!NOTE]  
> Members of the ``ldap_group_admin_dn`` group will receive harbor admin privledges.
> Users outside this group will have their ldap group(s) imported into harbor (under "groups" with type "ldap").
> These groups can be used for permissions assigned to a harbor "project".
