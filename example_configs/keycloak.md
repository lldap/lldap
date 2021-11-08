# KeyCloak configuration

Configuring [KeyCloak](https://www.keycloak.org) takes a bit of effort. Once
the KeyCloak instance is up and you logged in as admin (see [this
guide](https://www.keycloak.org/getting-started/getting-started-docker) to get
started with KeyCloak), you'll need to configure the LDAP mapping.

Keep in mind that LLDAP is _read-only_: that means that if you create some
users in KeyCloak, they won't be reflected to LLDAP. Instead, you should create
the user from LLDAP, and it will appear in KeyCloak. Same for groups. However,
you can set the permissions associated with users or groups in KeyCloak.

## Configure user authentication

In the admin console of KeyCloak, on the left, go to "User Federation". You can
then add an LDAP backend.

The key settings are:

 - Edit Mode: `READ_ONLY`
 - Vendor: `Other`
 - Username LDAP attribute: `uid`
 - UUID LDAP attribute: `uid`
 - User Object Classes: `person`
 - Connection URL: `ldap://<your-lldap-container>:3890`
 - Users DN: `ou=people,dc=example,dc=com` (or whatever `dc` you have)
 - Bind Type: `simple`
 - Bind DN: `admin` (your LLDAP admin user)
 - Bind Credential: your LLDAP admin password

Test the connection and authentication, it should work.

In the "Advanced Settings", you can "Query Supported Extensions", or just
enable the "LDAPv3 Password Modify Extended Operation".

Turn "Pagination" off.

Save the provider.

## Configure group mapping

Getting the LDAP groups to be imported into KeyCloak requires one more step:

Go back to "User Federation", and edit your LDAP integration. At the top, click
on the "Mappers" tab.

Find or create the `groups` mapper, with type `group-ldap-mapper`. The key
settings are:

  - LDAP Groups DN: `ou=groups,dc=example,dc=com` (or whatever `dc` you have)
  - Group Name LDAP Attribute: `cn`
  - Group Object Classes: `groupOfUniqueNames`
  - Mode: `READ_ONLY`

Save, then sync LDAP groups to KeyCloak, and (from the LDAP integration page)
sync the users to KeyCloak as well.

## Give the LDAP admin user admin rights to KeyCloak

Once the groups are synchronized, go to "Manage > Groups" on the left. Click on
`lldap_admin`, then "Edit".

Assign the role "admin" to the group. Now you can log in as the LLDAP admin to
the KeyCloak admin console.
