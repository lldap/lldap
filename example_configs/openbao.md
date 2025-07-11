# Configuration for OpenBao

OpenBao LDAP authentication configuration documentation is located [here](https://openbao.org/docs/auth/ldap/).

## User Interface

1. Navigate to `Access -> Authentication Methods`
2. Click `Enable new method +` in the top right and choose `LDAP` under `Infra`
3. Name the mounth path and click `Enable method` at the bottom

* URL: `ldap://lldap.example.com:3890` or `ldaps://lldap.example.com:6360`
* LDAP Options
    * If you're using LDAPS and your server does not have your LDAPS certificate installed check `Insecure TLS` otherwise leave this unchecked
    * User Attribute: `uid`
    * User Principal (UPN) Domain: **LEAVE THIS BLANK**
* Customize User Search
    * Name of Object to bind (binddn): `cn=admin,ou=people,dc=example,dc=com`
    * User DN: `ou=people,dc=example,dc=com`
    * Bindpass: `password`
    * User Search Filter: `(&(uid={{.Username}})(objectClass=person))`
* Customize Group Member Search
    * Group Filter: `(&(member={{.UserDN}})(objectclass=groupOfUniqueNames))`
    * Group Attribute: `cn`
    * Group DN: `ou=groups,dc=example,dc=com`

4. Click `Save` at the bottom
5. Click into the auth menthod and then `Create group +` under the `Groups` tab
6. Set the name of the LDAP group
7. Set policy the policy to attach to this group
8. Click `Save` at the bottom

Any user that is member of the group defined above will now be able to login via UI or CLI and get the associated policies.

```bash
bao login -method=<ldap-auth-mount-path> username=<user>
``` 

## CLI

1. Set BAO_ADDR environment variable 
    
    ```bash
    export BAO_ADDR=https://bao.example.com
    ```
2. Login to OpenBao and provide token when prompted

    ```bash
    bao login
    ````
3. Enable the LDAP authentication method

    ```bash
    bao auth enable ldap
    ```
4. Configure the LDAP authentication method

    ```bash
    bap write auth/ldap/config \
    url="ldap://lldap.example.com:3890" \
    binddn="cn=admin,ou=people,dc=example,dc=com" \
    bindpass="password" \
    userdn="ou=people,dc=example,dc=com" \
    userfilter="(&(uid={{.Username}})(objectClass=person))" \
    groupdn="ou=groups,dc=example,dc=com" \
    groupfilter="(&(member={{.UserDN}})(objectclass=groupOfUniqueNames))" \
    userattr="uid" \
    groupattr="cn" \
    discoverdn=false
    ```
    If you are using plain LDAP, change the URL accordingly. If you're using LDAPS and your server does not have your LDAPS certificate installed append `insecure_tls=true` to the bottom of the command.
    
5.  Add an LDAP group and attach a policy
    
    ```bash
    bao write auth/ldap/groups/bao_users policies=default
    ```

Any user that is member of the group defined above will now be able to login via UI or CLI and get the associated policies.
