# Configuration for OPNsense

## Create a LDAP Server

- Login to OPNsense
- Navigate to: `System > Access > Servers`
- Create a new server by clicking on the `+` icon

## Server Config

- Descriptive Name: `A Descriptive Name`
- Type: `LDAP`
- Hostname or IP address: `Hostname or IP for your LLDAP host`
- Port value: `Your LLDAP port`
  - Default: `3890`
- Transport: `TCP - Standard`
- Protocol version: `3`

Make sure the host running LLDAP is accessible to OPNsense and that you mapped the LLDAP port to the LLDAP host.

## LDAP Config

### Bind credentials

#### User DN

```
uid=admin,ou=people,dc=example,dc=com
```

It is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.

#### Password

```
xxx
```

Enter the password that you set for the user specified in the User DN field.

### Search Scope

```
One Level
```

### Base DN

```
dc=example,dc=com
```

This is the same LDAP Base DN that you set via the *LLDAP_LDAP_BASE_DN* environment variable or in `lldap_config.toml`.

### Authentication containers

```
ou=people,dc=example,dc=com
```

Note: The `Select` box may not work for selecting containers. You can just enter the `Authentication containers` directly into the text field.

### Extended Query

```
&(objectClass=person)(memberof=cn=lldap_admin,ou=groups,dc=example,dc=com)
```

It is recommended that you create a unique LDAP group (e.g., `lldap_opnsense`) in LLDAP and use that group in this query instead of `lldap_admin`. This will limit OPNsense access to  users in the `lldap_opnsense` group and make it easier to synchronize LLDAP groups with OPNsense groups for managing OPNsense access.

### Initial Template

```
OpenLDAP
```

### User naming attribute

```
uid
```

## Optional Configuration

The above configuration will connect OPNsense to LLDAP. This optional configuration will synchronize groups between LLDAP and OPNsense and automate user creation when an authorized LLDAP user logs into OPNsense.

### Remaining Server Configuration

Enable the following options on the OPNsense configuration page for your LLDAP server (the same page where you entered the prior configuration):

- Read Properties: `Checked`
- Synchronize groups: `Checked`
- Automatic user creation: `Checked`

### Create OPNsense Group

Go to `System > Access > Groups` and create a new group with the **same** name as the LLDAP group used to authenticate users for OPNsense.

By default, you would name your OPNsense group `lldap_admin` unless you followed the recommended advice in this guide and created a separate `lldap_opnsense` group for managing OPNsense users.

If you want your LLDAP users to have full administrator access in OPNsense, then you need to edit the `Assigned Privileges` for the group and add the `GUI - All pages` system privilege.

### Enable LLDAP as an Authentication Option

Go to `System > Settings > Administration` page and scroll down to the `Authentication` section. Add your LLDAP server configuration to the `Server` field.

## Testing LLDAP

OPNsense includes a built-in feature for testing user authentication at `System > Access > Tester`. Select your LLDAP server configuration in the `Authentication Server` to test logins for your LLDAP users.

## More Information

Please read the [OPNsense docs](https://docs.opnsense.org/manual/how-tos/user-ldap.html) for more information on LDAP configuration and managing access to OPNsense.
