# Proxmox VE Example

Proxmox Virtual Environment is a hyper-converged infrastructure open-source software. It is a hosted hypervisor that can run operating systems including Linux and Windows on x64 hardware. In this example we will setup user and group syncronization, with two example groups `proxmox_user` and `proxmox_admin`. This example was made using Proxmox VE 8.0.3. 

## Navigation

- From the `Server View` open the `Datacenter` page
- Then in this page, open the `Permissions > Realms` menu
- In this menu, select `Add > LDAP Server`

## General Options

- Realm: The internal proxmox name for this authentication method
- Base Domain Name: `dc=example,dc=com`
- User Attribute Name: `uid`
- Server: Your LLDAP hostname or IP
- Port: `3890`
- SSL: Leave unchecked unless you're using LDAPS
- Comment: This field will be exposed as the "name" in the login page

## Sync Options

- Bind User: `uid=admin,ou=people,dc=example,dc=com`
  - It is recommended that you create a separate user account (e.g, `bind_user`) instead of `admin` for sharing Bind credentials with other services. The `bind_user` should be a member of the `lldap_strict_readonly` group to limit access to your LDAP configuration in LLDAP.
- Bind Password: password of the user specified above
- E-Mail Attribute: `mail`
- Groupname attr: `cn`
- User Filter: `(&(objectClass=person)(|(memberof=cn=proxmox_user,ou=groups,dc=example,dc=com)(memberof=cn=proxmox_admin,ou=groups,dc=example,dc=com)))`
  - This filter will only copy users that are members of the `proxmox_user` or `proxmox_admin` groups. If you want to enable all users in lldap, this filter can be used: `(objectClass=person)`
- Group Filter: `(&(objectClass=groupofuniquenames)(|(cn=proxmox_user)(cn=proxmox_admin)))`
  - This filter will only copy the `proxmox_user` or `proxmox_admin` groups explicitly. If you want to sync all groups, this filter can be used: `(objectClass=groupofnames)`
- Default Sync Options:
  - Scope: `Users and Groups`
- Remove Vanished Options
  - Entry: Checked
  - Properties: Checked

## Syncronizing

Proxmox operates LDAP authentication by syncronizing with your lldap server to a local database. This sync can be triggered manually, and on a scheduled basis. Proxmox also offers a preview feature, which will report any changes to the local DB from a sync, without applying the changes. It is highly recommended to run a preview on your first syncronization after making any filter changes, to ensure syncronization is happening as expected.

### First Sync

- With the options saved, and from the `Permissions > Realms` page, select the LDAP realm you just created and click `Sync`
- At the sync dialog, click the Preview button, and carefully check the output to ensure all the users and groups you expect are seen, and that nothing is being remove unexpectedly.
- Once the preview output is matching what we expect, we can click the Sync button, on the `Realm Sync` dialog for the ldap realm we created.

### Scheduled Sync (Optional)

- Once we are confident that LDAP syncronizing is working as expected, this can be scheduled as a job from the `Permissions > Realms` page.
- On the second half of the page, click `Add` under `Realm Sync Jobs`
- Set a schedule for this job and click `Create`

## ACLs

Once you have users and groups syncronized from lldap, it is necessary to grant some perimssions to these users or groups so that they are able to use Proxmox. Proxmox handles this with a filesystem-like tree structure, and "roles" which are collections of permissions. In our basic example, we will grant the built-in `Administrator` role to our `proxmox_admin` role to the entire system. Then we will also grant the `proxmox_user` group several roles with different paths so they can clone and create VMs within a specific resource pool (`UserVMs`), but are otherwise restricted from editing or deleting other resources.

> Note that Promox appends the realm name to groups when syncing, so if you named your realm `lldap` the groups as synced will be `proxmox_user-lldap` and `proxmox_admin-lldap`

### Administrator

- From the Datacenter pane, select the `Permissions` menu page.
- Click `Add > Group Permission`
- Path: Type or select `/`
- Group: Type or select the admin group that has syncronized (`proxmox_admin-lldap` in our example)
- Role: `Administrator`
- Finish by clicking the `Add` button and this access should now be granted

### User Role

> This example assumes we have created Resource Pools named `UserVMs` and `Templates`

- From the Datacenter pane, select the `Permissions` menu page.
- We will be adding six rules in total, for each one clicking `Add > Group Permission`
  - Path: `/pool/UserVMs`, Group: `proxmox_user-lldap`, Role: PVEVMAdmin
  - Path: `/pool/UserVMs`, Group: `proxmox_user-lldap`, Role: PVEPoolAdmin
  - Path: `/pool/Templates`, Group: `proxmox_user-lldap`, Role: PVEPoolUser
  - Path: `/pool/Templates`, Group: `proxmox_user-lldap`, Role: PVETemplateUser
- The following two rules are based on a default setup of Proxmox, and may need to be updated based on your networking and storage configuration
  - Path: `/sdn/zones/localnetwork`, Group: `proxmox_user-lldap`, Role: PVESDNUser
  - Path: `/storage/local-lvm`, Group: `proxmox_user-lldap`, Role: PVEDatastoreUser

That completes our basic example. The ACL rules in Proxmox are very flexible though, and custom roles can be created as well. The Proxmox documentation on [User Management](https://pve.proxmox.com/wiki/User_Management) goes into more depth if you wish to write a policy that better fits your use case.
