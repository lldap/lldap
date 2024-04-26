# Configuration for pfSense

> [!NOTE]  
> Replace `dc=example,dc=com` with the same LDAP Base DN that you set via the *LLDAP_LDAP_BASE_DN* environment variable or in `lldap_config.toml`.

## Create a LDAP Server

- Login to pfSense
- Navigate to: `System > User Manager > Authentication Servers`
- Create a new server by clicking on the `+ Add` button

## LDAP Server Settings

- Descriptive Name: `A Descriptive Name`
- Type: `LDAP`
- Hostname or IP address: `Hostname or IP for your LLDAP host`
- Port value: `Your LLDAP port`
- Transport: `TCP - Standard`
- Protocol version: `3`
- Server Timeout: `25`

> [!NOTE]
> Make sure the host running LLDAP is accessible to pfSense and that you mapped the LLDAP port to the LLDAP host

### Search Scope
```
Entire Subtree
```
### Base DN

```
dc=example,dc=com
```

### Authentication containers

```
ou=people
```

> [!Note]
> The `Select a container` seach fuction will not work for selecting containers. You enter the `Authentication containers` directly into the text field.
> This is do to Pfsense running the following filter `"(|(ou=*)(cn=Users))"`, and `Organizational Units` is currently not supported.

### Extended Query

Enable extended query: 

- [X] `Checked`

### Query:

```
&(objectClass=person)(|(memberof=cn=pfsense_admin,ou=groups,dc=example,dc=com)(memberof=cn=pfsense_guest,ou=groups,dc=example,dc=com))
```

This example gives you two groups in LLDAP, one for pfSense admin access (`pfsense_admin`) and one for guest access (`pfsense_guest`). You **must** create these exact same groups in both LLDAP and pfSense, then give them the correct permissions in pfSense.

### Bind Anonymous

- [ ] `Unchecked`

### Bind credentials

#### User DN

```
uid=yourbinduser,ou=people,dc=example,dc=com
```

It is recommended that you create a separate read-only user account (e.g, `readonly`) instead of `admin` for sharing Bind credentials with other services. The `readonly` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.

#### Password

```
LLDAPPasswordForBindUser
```

### User naming attribute
```
uid
```
### Group naming attribute
```
cn
```
### Group member attribute
```
memberof
```
### RFC 2307 Groups

- [ ] `Unchecked`

### Group Object Class
```
groupOfUniqueNames
```

### Shell Authentication Group DN
```
cn=pfsense_admin,ou=groups,dc=example,dc=com
```

(This is only if you want to give a group shell access through LDAP. Leave blank and only the pfSense admin user will have shell access.

### Remaining Server Configuration

Enable the following options on the pfSense configuration page for your LLDAP server (the same page where you entered the prior configuration):

- [X] UTF8 Encodes: `Checked`
- [ ] Username Alterations: `Unchecked`
- [ ] Allow unauthenticated bind: `Unchecked`

### Create pfSense Groups

Go to `System > User Manager > Groups` and create a new group(s) with the **same exact** name as the LLDAP group(s) used to authenticate users for pfSense (`pfsense_admin` and `pfsense_guest` in this example).

If you want your LLDAP users to have full administrator access in pfSense, then you need to edit the `Assigned Privileges` for the group and add the `WebCfg - All pages` system privilege. If you do not give any permissions to a group, you will be able to log in but only see an empty webUI.

### Enable LLDAP as an Authentication Option

Go to `System > User Manager > Settings` page. Add your LLDAP server configuration to the `Authentication Server` field. **The "Save & Test" Button will fail the test results at step 3. No clue why.**

## Testing LLDAP

pfSense includes a built-in feature for testing user authentication at `Diagnostics > Authentication`. Select your LLDAP server configuration in the `Authentication Server` to test logins for your LLDAP users. The groups (only the ones you added to pfSense) should show up when tested.

> [!WARNING] 
> When running `Save and test`, the `Attempting to fetch Organizational Units from` will fail. This is do to Pfsense running the following filter `"(|(ou=*)(cn=Users))"`, and `Organizational Units` is currently not supported.

## More Information

Please read the [pfSense docs](https://docs.netgate.com/pfsense/en/latest/usermanager/ldap.html) for more information on LDAP configuration and managing access to pfSense.
