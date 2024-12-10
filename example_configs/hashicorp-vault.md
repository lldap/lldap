# Configuration for HashiCorp Vault

Official LDAP configuration documentation is located [here](https://developer.hashicorp.com/vault/docs/auth/ldap).

**You'll need to authenticate using your root token or as a user who has permission to modify authentication methods!**

## User Interface

1. Navigate to `Access -> Authentication Methods`
2. Click `Enable new method +` in the top right and choose `LDAP` under `Infra`
3. Name the path whatever you want (preferably keep it default) and click `Enable method` at the bottom

* URL: `ldap://lldap.example.com:3890` or `ldaps://lldap.example.com:6360`
* LDAP Options
    * If you're using LDAPS and your server does not have your LDAPS certificate installed check `Insecure TLS` otherwise leave this unchecked
    * User Attribute: `uid`
    * User Principal (UPN) Domain: **LEAVE THIS BLANK**
* Customize User Search
    * Name of Object to bind (binddn): `cn=admin,ou=people,dc=example,dc=com`
    * User DN: `ou=people,dc=example,dc=com`
    * Bindpass: `ChangeMe!`
    * User Search Filter: `(&(uid={{.Username}})(objectClass=person))`
* Customize Group Member Search
    * Group Filter: `(&(member={{.UserDN}})(objectclass=groupOfUniqueNames))`
    * Group Attribute: `cn`
    * Group DN: `ou=groups,dc=example,dc=com`

4. Click `Save` at the bottom
5. Click into the auth menthod and then `Create group +` under the `Groups` tab
6. Set the name as the group you want users to have to authenticate to HashiCorp Vault
7. Set policy as `default` or whatever policy you want to tie to this group
8. Click `Save` at the bottom

As long as your user is in the group you specified, you should now be able to select `LDAP` from the dropdown on the login page and use your credentials.

## CLI

**This requires the vault CLI to be installed on your machine**

1. Set VAULT_ADDR environment variable 
    
    ```bash
    export VAULT_ADDR=https://vault.example.com
    ```
2. Login to vault and provide token when prompted

    ```bash
    vault login
    ````
3. Enable the LDAP authentication method

    ```bash
    vault auth enable ldap
    ```
4. Configure the LDAP authentication method

    ```bash
    vault write auth/ldap/config \
    url="ldaps://lldaps.example.com:6360" \
    binddn="cn=admin,ou=people,dc=example,dc=com" \
    bindpass="ChangeMe!" \
    userdn="ou=people,dc=example,dc=com" \
    userfilter="(&(uid={{.Username}})(objectClass=person))" \
    groupdn="ou=groups,dc=example,dc=com" \
    groupfilter="(&(member={{.UserDN}})(objectclass=groupOfUniqueNames))" \
    userattr="uid" \
    groupattr="cn" \
    discoverdn=false
    ```
    If you are using plain LDAP, change the URL accordingly. If you're using LDAPS and your server does not have your LDAPS certificate installed append `insecure_tls=true` to the bottom of the command.
5.  Add your group to the LDAP configuration and set the policy
    
    ```bash
    vault write auth/ldap/groups/vault_users policies=default
    ```

As long as your user is in the group you specified, you should now be able to select `LDAP` from the dropdown on the login page and use your credentials.